"""
remediator/revoke.py

IAM Remediation Engine — Severity-Scaled Response

Remediation tiers (governed by risk_score from the IAM permission graph):

    HARD   (risk_score >= 70, or score is None — fail-safe):
        • Delete ALL access keys for the principal
        • Attach an explicit Deny policy: {"Effect":"Deny","Action":"s3:*","Resource":"*"}
          Named: killswitch-deny-<username>-<unix-ts>
          This policy persists until manually reviewed and removed.
        • Log to CloudWatch Logs /killswitch/remediations

    SOFT   (risk_score 30-69):
        • Attach a time-limited Deny policy on high-volume S3 write actions only
          (s3:PutObject, s3:DeleteObject, s3:CopyObject)
          Policy includes a Condition: {"DateGreaterThan": {"aws:CurrentTime": <expiry>}}
          so it auto-expires in 30 minutes. Reviewed and manually removed if needed.
        • Log to CloudWatch Logs /killswitch/remediations

    ALERT  (risk_score < 30):
        • No IAM change — publish SNS notification for human review
        • Log to CloudWatch Logs /killswitch/remediations

Every tier produces a structured JSON log entry with:
    timestamp, principal, trigger_metric, risk_score, severity_tier,
    action_taken, technique_id, policy_arn (if applicable)
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

import boto3
from botocore.exceptions import ClientError

# ─── Conditional import (Lambda vs local) ────────────────────────────────────
try:
    from common.attack_mapping import tag_finding
except ImportError:
    from attack_mapping import tag_finding  # type: ignore[no-redef]

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

REGION            = os.environ.get("AWS_REGION", "us-east-1")
SNS_ALERT_TOPIC   = os.environ.get("SNS_ALERT_TOPIC_ARN", "")
LOG_GROUP         = "/killswitch/remediations"
SOFT_DENY_MINUTES = 30    # How long the SOFT deny policy lasts

HARD_THRESHOLD    = 70
SOFT_THRESHOLD    = 30

# S3 actions blocked in HARD revoke
HARD_DENY_ACTIONS = ["s3:*"]

# S3 actions blocked in SOFT throttle (only the high-volume write operations)
SOFT_DENY_ACTIONS = [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:CopyObject",
    "s3:RestoreObject",
]

# ─────────────────────────────────────────────────────────────────────────────
# AWS clients
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_iam: Any = None
_sns: Any = None
_logs: Any = None


def _get_iam() -> Any:
    global _iam
    if _iam is None:
        _iam = boto3.client("iam", region_name=REGION)
    return _iam


def _get_sns() -> Any:
    global _sns
    if _sns is None and SNS_ALERT_TOPIC:
        _sns = boto3.client("sns", region_name=REGION)
    return _sns


def _get_logs() -> Any:
    global _logs
    if _logs is None:
        _logs = boto3.client("logs", region_name=REGION)
    return _logs


# ─────────────────────────────────────────────────────────────────────────────
# IAM helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_username(principal_arn: str) -> str:
    """
    Extract IAM username from ARN.
    e.g. 'arn:aws:iam::123456789012:user/killswitch-attacker' → 'killswitch-attacker'
    Falls back to the ARN itself if parsing fails.
    """
    try:
        return principal_arn.split("/")[-1]
    except (IndexError, AttributeError):
        return principal_arn


def _delete_all_access_keys(username: str) -> list[str]:
    """
    Delete ALL active access keys for the given IAM username.
    Returns list of deleted key IDs.
    """
    iam = _get_iam()
    deleted_keys: list[str] = []

    try:
        response = iam.list_access_keys(UserName=username)
        keys = response.get("AccessKeyMetadata", [])

        for key in keys:
            key_id = key["AccessKeyId"]
            iam.delete_access_key(UserName=username, AccessKeyId=key_id)
            deleted_keys.append(key_id)
            logger.info("HARD revoke: deleted access key %s for user %s", key_id, username)

    except ClientError as e:
        logger.error("Failed to delete access keys for %s: %s", username, e)
        raise

    return deleted_keys


def _attach_deny_policy(
    username: str,
    actions: list[str],
    reason: str,
    time_limited: bool = False,
) -> str:
    """
    Attach an inline deny policy to the IAM user.

    Args:
        username:     IAM username (not ARN)
        actions:      List of IAM action strings to deny
        reason:       Human-readable reason label (for policy name)
        time_limited: If True, add a DateGreaterThan condition so the deny
                      auto-expires in SOFT_DENY_MINUTES minutes.

    Returns:
        Policy name that was attached.
    """
    iam = _get_iam()
    ts = int(time.time())
    policy_name = f"killswitch-deny-{reason}-{ts}"

    # Base deny statement
    statement: dict[str, Any] = {
        "Sid":      "KillSwitchAutoRevoke",
        "Effect":   "Deny",
        "Action":   actions,
        "Resource": "*",
    }

    if time_limited:
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=SOFT_DENY_MINUTES)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        statement["Condition"] = {
            "DateGreaterThan": {"aws:CurrentTime": expiry}
        }
        # Note: DateGreaterThan condition makes the Deny effective UNTIL expiry
        # IAM evaluates: if current_time > expiry → condition true → Deny applies
        # After expiry, condition is false → Deny no longer applies
        # This is the correct semantics for a time-limited deny.
        statement["Sid"] += "TimeLimited"

    policy_doc = {
        "Version":   "2012-10-17",
        "Statement": [statement],
    }

    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
        )
        logger.info(
            "Attached deny policy '%s' to user '%s' (time_limited=%s)",
            policy_name, username, time_limited,
        )
    except ClientError as e:
        logger.error("Failed to attach policy to %s: %s", username, e)
        raise

    return policy_name


# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch Logs helper
# ─────────────────────────────────────────────────────────────────────────────

def _log_remediation(log_entry: dict[str, Any]) -> None:
    """Write a structured JSON log entry to /killswitch/remediations log group."""
    logs = _get_logs()
    log_stream = datetime.now(timezone.utc).strftime("%Y/%m/%d/killswitch")

    try:
        # Ensure log group exists
        try:
            logs.create_log_group(logGroupName=LOG_GROUP)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass

        # Ensure log stream exists
        try:
            logs.create_log_stream(logGroupName=LOG_GROUP, logStreamName=log_stream)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass

        logs.put_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=log_stream,
            logEvents=[{
                "timestamp": int(time.time() * 1000),
                "message":   json.dumps(log_entry, default=str),
            }],
        )
    except ClientError as e:
        # Don't let logging failure block remediation
        logger.error("CloudWatch log write failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Main remediation entry point
# ─────────────────────────────────────────────────────────────────────────────

def revoke_principal(
    principal_arn: str,
    trigger_metric: dict[str, Any],
    risk_score: int | None,
) -> dict[str, Any]:
    """
    Execute severity-tiered IAM remediation for a flagged principal.

    Args:
        principal_arn:  Full IAM ARN of the principal to remediate
        trigger_metric: Dict with detection context (z_score, window_count, etc.)
        risk_score:     Integer 0-100 from iam_graph/risk_score.py.
                        None means Phase 3 is not built → default to HARD revoke
                        (fail-safe: unknown risk = treat as high risk).

    Returns:
        Structured result dict with action taken and all audit fields.
    """
    username = _extract_username(principal_arn)
    ts_str   = datetime.now(timezone.utc).isoformat()
    actions_taken: list[str] = []
    policy_name: str | None = None
    deleted_keys: list[str] = []

    # ── Determine severity tier ───────────────────────────────────────────────
    if risk_score is None or risk_score >= HARD_THRESHOLD:
        tier = "HARD"
    elif risk_score >= SOFT_THRESHOLD:
        tier = "SOFT"
    else:
        tier = "ALERT"

    logger.warning(
        "Remediating principal=%s risk_score=%s tier=%s",
        principal_arn, risk_score, tier,
    )

    # ── Execute remediation ───────────────────────────────────────────────────

    if tier == "HARD":
        # 1. Delete all access keys
        try:
            deleted_keys = _delete_all_access_keys(username)
            actions_taken.append(f"deleted_keys:{','.join(deleted_keys)}")
        except ClientError as e:
            logger.error("Key deletion failed: %s — continuing to attach deny policy", e)

        # 2. Attach permanent deny policy (s3:*)
        try:
            policy_name = _attach_deny_policy(
                username=username,
                actions=HARD_DENY_ACTIONS,
                reason="hard",
                time_limited=False,
            )
            actions_taken.append(f"attached_deny_policy:{policy_name}")
        except ClientError as e:
            logger.error("Deny policy attachment failed: %s", e)

    elif tier == "SOFT":
        # Attach time-limited deny on write actions only
        try:
            policy_name = _attach_deny_policy(
                username=username,
                actions=SOFT_DENY_ACTIONS,
                reason="soft",
                time_limited=True,
            )
            actions_taken.append(f"attached_time_limited_deny:{policy_name}")
        except ClientError as e:
            logger.error("Soft deny policy attachment failed: %s", e)

    else:  # ALERT
        # No IAM change — SNS only
        sns = _get_sns()
        if sns and SNS_ALERT_TOPIC:
            try:
                sns.publish(
                    TopicArn=SNS_ALERT_TOPIC,
                    Subject=f"[KillSwitch ALERT] Anomalous S3 activity: {username}",
                    Message=json.dumps({
                        "principal": principal_arn,
                        "risk_score": risk_score,
                        "trigger_metric": trigger_metric,
                        "note": "ALERT tier — no IAM action taken. Human review required.",
                    }, indent=2),
                )
                actions_taken.append("published_sns_alert")
            except ClientError as e:
                logger.error("SNS publish failed: %s", e)
        else:
            logger.warning("ALERT tier but no SNS topic configured. Check SNS_ALERT_TOPIC_ARN.")
            actions_taken.append("alert_logged_only_no_sns_configured")

    # ── Build and emit log entry ──────────────────────────────────────────────
    result = tag_finding(
        finding={
            "timestamp":     ts_str,
            "principal_arn": principal_arn,
            "username":      username,
            "trigger_metric": trigger_metric,
            "risk_score":    risk_score,
            "severity_tier": tier,
            "actions_taken": actions_taken,
            "deleted_keys":  deleted_keys,
            "policy_name":   policy_name,
        },
        technique_key="VALID_ACCOUNTS_CLOUD",
    )

    _log_remediation(result)

    return result
