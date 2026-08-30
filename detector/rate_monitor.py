"""
detector/rate_monitor.py

CloudTrail S3 Data Event Processor — Per-Principal Adaptive Baseline Detector

ALGORITHM — Statistical threshold (NOT machine learning):
    This module implements an Exponentially Weighted Moving Average (EWMA)
    of each principal's per-minute PUT/DELETE event count. An anomaly is
    flagged when the current window's count deviates by more than a
    configurable number of standard deviations from that principal's own
    historical baseline — NOT against a single global number.

    This means a principal that normally processes 500 objects/min will NOT
    be flagged at the same absolute threshold as one that normally does 5/min.

    Specifically:
        new_ewma     = α·x + (1−α)·old_ewma
        new_ewma_var = (1−α)·(old_var + α·(x − old_ewma)²)
        z_score      = (x − ewma) / sqrt(ewma_var + ε)

    Flag when: z > Z_THRESHOLD  OR  x > RATE_MULTIPLIER · ewma
    (The rate multiplier catches new principals with very few observations
    where the variance estimate isn't yet stable enough for z-score alone.)

    EWMA reference: "Exponentially Weighted Moving Average" — Holt (1957)

State store: DynamoDB table killswitch-baselines
    Per-principal item contains EWMA rate, variance, window counter,
    window start timestamp, and observation count.

Lambda entry point: handler(event, context)
    Called by EventBridge whenever a CloudTrail S3 data event fires.
    CloudTrail event is embedded in event["detail"].
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from datetime import datetime, timezone
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

import boto3
from botocore.exceptions import ClientError

# ─── Conditional import: works both as Lambda and as local module ─────────────
try:
    from common.attack_mapping import tag_finding
    from remediator.revoke import revoke_principal
except ImportError:
    # Running as Lambda ZIP — modules are at package root
    from attack_mapping import tag_finding  # type: ignore[no-redef]
    from revoke import revoke_principal     # type: ignore[no-redef]

# ─────────────────────────────────────────────────────────────────────────────
# Configuration (from environment variables — set via Lambda config or .env)
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_TABLE         = os.environ.get("BASELINE_TABLE", "killswitch-baselines")
REGION                 = os.environ.get("AWS_REGION", "us-east-1")
EWMA_ALPHA             = float(os.environ.get("EWMA_ALPHA", "0.3"))
Z_SCORE_THRESHOLD      = float(os.environ.get("Z_SCORE_THRESHOLD", "4.0"))
RATE_MULTIPLIER        = float(os.environ.get("RATE_MULTIPLIER_THRESHOLD", "10.0"))
WINDOW_SECONDS         = int(os.environ.get("WINDOW_SECONDS", "60"))
MIN_OBSERVATIONS       = int(os.environ.get("MIN_OBSERVATIONS", "5"))
EPSILON                = 1e-6   # avoids division-by-zero in stddev

# Event names we track for rate anomaly detection
TRACKED_EVENT_NAMES = {"PutObject", "DeleteObject", "CopyObject", "RestoreObject"}

# ─────────────────────────────────────────────────────────────────────────────
# AWS clients — initialised outside handler for Lambda warm-start reuse
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_dynamodb: boto3.client | None = None


def _get_dynamodb() -> Any:
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.client("dynamodb", region_name=REGION)
    return _dynamodb


# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_principal_state(principal_arn: str) -> dict[str, Any]:
    """
    Load EWMA baseline state for a principal from DynamoDB.
    Returns default zero-state if principal is new (first time we've seen them).
    """
    ddb = _get_dynamodb()
    try:
        response = ddb.get_item(
            TableName=BASELINE_TABLE,
            Key={"principal_arn": {"S": principal_arn}},
            ConsistentRead=True,
        )
    except ClientError as e:
        logger.error("DynamoDB get_item failed for %s: %s", principal_arn, e)
        raise

    item = response.get("Item", {})
    now = time.time()

    return {
        "ewma_rate":         float(item.get("ewma_rate", {}).get("N", "0.0")),
        "ewma_var":          float(item.get("ewma_var", {}).get("N", "1.0")),
        "window_count":      int(item.get("window_count", {}).get("N", "0")),
        "window_start":      float(item.get("window_start", {}).get("N", str(now))),
        "observation_count": int(item.get("observation_count", {}).get("N", "0")),
        "risk_score":        _parse_optional_int(item.get("risk_score")),
    }


def _save_principal_state(principal_arn: str, state: dict[str, Any]) -> None:
    """Persist updated EWMA state back to DynamoDB (full item overwrite)."""
    ddb = _get_dynamodb()
    try:
        ddb.put_item(
            TableName=BASELINE_TABLE,
            Item={
                "principal_arn":    {"S": principal_arn},
                "ewma_rate":        {"N": str(state["ewma_rate"])},
                "ewma_var":         {"N": str(state["ewma_var"])},
                "window_count":     {"N": str(state["window_count"])},
                "window_start":     {"N": str(state["window_start"])},
                "observation_count":{"N": str(state["observation_count"])},
                "last_updated":     {"S": datetime.now(timezone.utc).isoformat()},
                # risk_score is written by iam_graph/risk_score.py; preserve if present
                **({"risk_score": {"N": str(state["risk_score"])}}
                   if state.get("risk_score") is not None else {}),
            },
        )
    except ClientError as e:
        logger.error("DynamoDB put_item failed for %s: %s", principal_arn, e)
        raise


def _parse_optional_int(attr: dict | None) -> int | None:
    if attr is None:
        return None
    return int(attr.get("N", "0"))


# ─────────────────────────────────────────────────────────────────────────────
# EWMA baseline update
# ─────────────────────────────────────────────────────────────────────────────

def _update_ewma(old_rate: float, old_var: float, new_value: float) -> tuple[float, float]:
    """
    Update EWMA mean and variance estimates.

    EWMA mean:     μ_t = α·x_t + (1−α)·μ_{t−1}
    EWMA variance: σ²_t = (1−α)·(σ²_{t−1} + α·(x_t − μ_{t−1})²)

    Args:
        old_rate:  Previous EWMA estimate of per-window rate
        old_var:   Previous EWMA estimate of variance
        new_value: Observed count for the just-completed window

    Returns:
        (new_ewma_rate, new_ewma_var)
    """
    alpha = EWMA_ALPHA
    new_rate = alpha * new_value + (1 - alpha) * old_rate
    new_var  = (1 - alpha) * (old_var + alpha * (new_value - old_rate) ** 2)
    # Floor variance to avoid collapsing to near-zero (which would make every
    # deviation look like a 4σ event for stable principals)
    new_var = max(new_var, 0.25)
    return new_rate, new_var


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly evaluation
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate_window(
    window_count: int,
    ewma_rate: float,
    ewma_var: float,
    observation_count: int,
) -> dict[str, Any]:
    """
    Evaluate whether a completed 60s window represents an anomaly.

    Returns a dict with:
        flagged:          bool — True if anomaly detected
        z_score:          float
        rate_multiplier:  float (window_count / ewma_rate)
        flag_reason:      str | None
    """
    if observation_count < MIN_OBSERVATIONS:
        # Not enough history yet — don't flag (cold-start protection)
        return {
            "flagged":         False,
            "z_score":         None,
            "rate_multiplier": None,
            "flag_reason":     f"insufficient_history ({observation_count}/{MIN_OBSERVATIONS} observations)",
        }

    if ewma_rate < EPSILON:
        # Baseline is effectively zero — any activity is suspicious but
        # we need at least one non-zero window to establish a real baseline.
        # Flag only if above rate multiplier threshold.
        rate_multiplier = float("inf")
        flagged = window_count > 0
        return {
            "flagged":         flagged,
            "z_score":         None,
            "rate_multiplier": rate_multiplier,
            "flag_reason":     "zero_baseline_activity" if flagged else None,
        }

    stddev = math.sqrt(ewma_var + EPSILON)
    z_score = (window_count - ewma_rate) / stddev
    rate_multiplier = window_count / ewma_rate

    flagged = False
    flag_reason = None

    if z_score > Z_SCORE_THRESHOLD:
        flagged = True
        flag_reason = f"z_score={z_score:.2f} > threshold={Z_SCORE_THRESHOLD}"
    elif rate_multiplier > RATE_MULTIPLIER:
        flagged = True
        flag_reason = f"rate_multiplier={rate_multiplier:.2f}x > threshold={RATE_MULTIPLIER}x"

    return {
        "flagged":         flagged,
        "z_score":         round(z_score, 3),
        "rate_multiplier": round(rate_multiplier, 3),
        "flag_reason":     flag_reason,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CloudTrail event parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cloudtrail_event(eb_event: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extract relevant fields from an EventBridge-wrapped CloudTrail event.

    EventBridge delivers CloudTrail events in this envelope:
        {
          "source": "aws.s3",
          "detail-type": "AWS API Call via CloudTrail",
          "detail": { ...CloudTrail record... }
        }

    Returns None if the event is not an S3 data event we care about.
    """
    detail = eb_event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name not in TRACKED_EVENT_NAMES:
        return None

    user_identity = detail.get("userIdentity", {})
    principal_arn = (
        user_identity.get("arn")
        or user_identity.get("principalId", "unknown")
    )

    request_params = detail.get("requestParameters") or {}
    bucket_name    = request_params.get("bucketName", "unknown")
    object_key     = request_params.get("key", "unknown")

    return {
        "principal_arn": principal_arn,
        "event_name":    event_name,
        "event_time":    detail.get("eventTime", ""),
        "bucket_name":   bucket_name,
        "object_key":    object_key,
        "source_ip":     detail.get("sourceIPAddress", ""),
        "user_agent":    detail.get("userAgent", ""),
        "identity_type": user_identity.get("type", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main processing logic
# ─────────────────────────────────────────────────────────────────────────────

def _process_event(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Core per-event logic:
      1. Load this principal's EWMA state from DynamoDB
      2. Increment window counter
      3. If window has expired: evaluate anomaly, update EWMA, reset window
      4. If anomaly: trigger remediator
      5. Emit structured log entry

    Returns the structured log entry (for testing / CloudWatch Logs).
    """
    principal_arn = parsed["principal_arn"]
    now = time.time()

    state = _load_principal_state(principal_arn)

    window_elapsed = now - state["window_start"]
    window_expired = window_elapsed >= WINDOW_SECONDS

    # Always increment window counter for this event
    state["window_count"] += 1

    anomaly_result: dict[str, Any] = {"flagged": False}

    if window_expired:
        # ── Window boundary ──────────────────────────────────────────────────
        # 1. Evaluate the window that just closed
        anomaly_result = _evaluate_window(
            window_count=state["window_count"],
            ewma_rate=state["ewma_rate"],
            ewma_var=state["ewma_var"],
            observation_count=state["observation_count"],
        )

        # 2. Update EWMA with completed window count
        new_rate, new_var = _update_ewma(
            old_rate=state["ewma_rate"],
            old_var=state["ewma_var"],
            new_value=float(state["window_count"]),
        )

        # 3. Reset window
        state["ewma_rate"]         = new_rate
        state["ewma_var"]          = new_var
        state["window_count"]      = 1   # count the current triggering event
        state["window_start"]      = now
        state["observation_count"] += 1

    _save_principal_state(principal_arn, state)

    # ── Build structured log entry ───────────────────────────────────────────
    log_entry: dict[str, Any] = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "principal_arn":   principal_arn,
        "event_name":      parsed["event_name"],
        "bucket":          parsed["bucket_name"],
        "window_count":    state["window_count"] - 1,  # count before reset
        "ewma_rate":       round(state["ewma_rate"], 3),
        "ewma_stddev":     round(math.sqrt(state["ewma_var"] + EPSILON), 3),
        "z_score":         anomaly_result.get("z_score"),
        "rate_multiplier": anomaly_result.get("rate_multiplier"),
        "observation_count": state["observation_count"],
        "window_evaluated":  window_expired,
        "flagged":           anomaly_result["flagged"],
        "flag_reason":       anomaly_result.get("flag_reason"),
        "risk_score":        state.get("risk_score"),
    }

    if anomaly_result["flagged"]:
        # Choose technique based on event type
        technique_key = (
            "DATA_DESTRUCTION"
            if parsed["event_name"] == "DeleteObject"
            else "DATA_ENCRYPTED_FOR_IMPACT"
            if parsed["event_name"] == "PutObject"
            else "VALID_ACCOUNTS_CLOUD"
        )
        log_entry = tag_finding(log_entry, technique_key)

        logger.warning(
            "ANOMALY DETECTED principal=%s z=%.2f reason=%s — triggering remediator",
            principal_arn,
            anomaly_result.get("z_score") or 0.0,
            anomaly_result.get("flag_reason"),
        )

        trigger_metric = {
            "window_count":    log_entry["window_count"],
            "ewma_rate":       log_entry["ewma_rate"],
            "ewma_stddev":     log_entry["ewma_stddev"],
            "z_score":         log_entry["z_score"],
            "rate_multiplier": log_entry["rate_multiplier"],
            "flag_reason":     log_entry["flag_reason"],
            "bucket":          parsed["bucket_name"],
            "event_time":      parsed["event_time"],
        }

        revocation_result = revoke_principal(
            principal_arn=principal_arn,
            trigger_metric=trigger_metric,
            risk_score=state.get("risk_score"),
        )
        log_entry["remediation"] = revocation_result
    else:
        logger.info(
            "normal principal=%s window_count=%d ewma_rate=%.2f z=%s",
            principal_arn,
            log_entry["window_count"],
            log_entry["ewma_rate"],
            log_entry.get("z_score"),
        )

    return log_entry


# ─────────────────────────────────────────────────────────────────────────────
# Lambda entry point
# ─────────────────────────────────────────────────────────────────────────────

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler — invoked by EventBridge when a CloudTrail S3 data
    event fires on the monitored test bucket.

    Supports both single-event and batched EventBridge delivery.
    """
    logger.info("Received EventBridge event: %s", json.dumps(event, default=str))

    # EventBridge delivers one CloudTrail record per invocation
    parsed = _parse_cloudtrail_event(event)
    if parsed is None:
        logger.info("Skipping non-tracked event: %s", event.get("detail", {}).get("eventName"))
        return {"statusCode": 200, "body": "ignored"}

    result = _process_event(parsed)

    return {
        "statusCode": 200,
        "body": json.dumps(result, default=str),
    }
