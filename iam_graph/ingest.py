"""
iam_graph/ingest.py

IAM Policy Ingestion — Pull all IAM policies from the AWS account via boto3.

Uses GetAccountAuthorizationDetails — a single API call that returns:
    • All IAM users (with inline + attached policies)
    • All IAM groups (with inline + attached policies)
    • All IAM roles (with inline + attached policies, trust policies)
    • All managed policies (all versions, with policy document JSON)

Output: Writes a normalized JSON cache file to iam_graph/cache/iam_snapshot.json
        This cache is the input to graph_builder.py.

Usage:
    python iam_graph/ingest.py [--output iam_graph/cache/iam_snapshot.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

REGION = os.environ.get("AWS_REGION", "us-east-1")

# Default output path (relative to repo root)
DEFAULT_OUTPUT = Path(__file__).parent / "cache" / "iam_snapshot.json"


# ─────────────────────────────────────────────────────────────────────────────
# IAM ingestion
# ─────────────────────────────────────────────────────────────────────────────

def fetch_account_authorization_details(iam: Any) -> dict[str, list]:
    """
    Paginate through GetAccountAuthorizationDetails to retrieve ALL
    users, groups, roles, and managed policies in the account.

    Returns a dict with keys: UserDetailList, GroupDetailList,
    RoleDetailList, Policies.
    """
    results: dict[str, list] = {
        "UserDetailList":  [],
        "GroupDetailList": [],
        "RoleDetailList":  [],
        "Policies":        [],
    }

    paginator = iam.get_paginator("get_account_authorization_details")
    filters = ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]

    logger.info("Fetching IAM authorization details (this may take a moment)...")

    for page in paginator.paginate(Filter=filters):
        results["UserDetailList"].extend(page.get("UserDetailList", []))
        results["GroupDetailList"].extend(page.get("GroupDetailList", []))
        results["RoleDetailList"].extend(page.get("RoleDetailList", []))
        results["Policies"].extend(page.get("Policies", []))

    logger.info(
        "Fetched: %d users, %d groups, %d roles, %d managed policies",
        len(results["UserDetailList"]),
        len(results["GroupDetailList"]),
        len(results["RoleDetailList"]),
        len(results["Policies"]),
    )
    return results


def _decode_policy_doc(raw: Any) -> dict | None:
    """Policy documents from GetAccountAuthorizationDetails are URL-encoded JSON strings."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw  # already decoded (some API responses decode automatically)
    if isinstance(raw, str):
        import urllib.parse
        try:
            return json.loads(urllib.parse.unquote(raw))
        except (json.JSONDecodeError, ValueError):
            logger.warning("Could not decode policy document: %s...", str(raw)[:100])
            return None
    return None


def normalize_principal(principal_type: str, detail: dict) -> dict:
    """
    Normalize an IAM user, group, or role detail record into a flat structure
    that graph_builder.py can consume.
    """
    arn = detail.get("Arn", "")
    name = detail.get("UserName") or detail.get("GroupName") or detail.get("RoleName", "unknown")

    # Inline policies
    inline_policies: list[dict] = []
    for ip in detail.get("UserPolicyList", []) + detail.get("GroupPolicyList", []) + detail.get("RolePolicyList", []):
        doc = _decode_policy_doc(ip.get("PolicyDocument"))
        if doc:
            inline_policies.append({
                "policy_name":     ip.get("PolicyName", ""),
                "policy_document": doc,
                "policy_type":     "inline",
            })

    # Attached managed policies
    attached_policies: list[dict] = []
    for ap in detail.get("AttachedManagedPolicies", []):
        attached_policies.append({
            "policy_name": ap.get("PolicyName", ""),
            "policy_arn":  ap.get("PolicyArn", ""),
            "policy_type": "managed",
        })

    # Trust policy (roles only)
    trust_policy = None
    if principal_type == "role":
        raw_trust = detail.get("AssumeRolePolicyDocument")
        trust_policy = _decode_policy_doc(raw_trust)

    # Group membership (users only)
    group_list = [g.get("GroupName", "") for g in detail.get("GroupList", [])]

    return {
        "arn":               arn,
        "name":              name,
        "principal_type":    principal_type,
        "inline_policies":   inline_policies,
        "attached_policies": attached_policies,
        "trust_policy":      trust_policy,
        "groups":            group_list,  # only populated for users
        "path":              detail.get("Path", "/"),
        "create_date":       str(detail.get("CreateDate", "")),
    }


def normalize_managed_policy(policy_detail: dict) -> dict | None:
    """
    Extract the default policy version document from a managed policy record.
    Returns None if no usable document is found.
    """
    arn  = policy_detail.get("Arn", "")
    name = policy_detail.get("PolicyName", "")
    default_version = policy_detail.get("DefaultVersionId", "v1")

    # Find the matching version document in PolicyVersionList
    doc = None
    for version in policy_detail.get("PolicyVersionList", []):
        if version.get("VersionId") == default_version and version.get("IsDefaultVersion"):
            doc = _decode_policy_doc(version.get("Document"))
            break

    if not doc:
        # Some policies may not have the document embedded (e.g., AWS managed)
        # We still record the policy for graph completeness
        pass

    return {
        "arn":             arn,
        "name":            name,
        "policy_type":     "managed",
        "is_aws_managed":  arn.startswith("arn:aws:iam::aws:"),
        "document":        doc,
        "version":         default_version,
    }


def build_snapshot(raw: dict[str, list], account_id: str) -> dict:
    """
    Convert raw GetAccountAuthorizationDetails output into a normalized snapshot
    ready for ingestion by graph_builder.py.
    """
    snapshot: dict[str, Any] = {
        "meta": {
            "account_id":    account_id,
            "captured_at":   datetime.now(timezone.utc).isoformat(),
            "region":        REGION,
        },
        "principals": [],
        "managed_policies": [],
    }

    # Users
    for user in raw["UserDetailList"]:
        snapshot["principals"].append(normalize_principal("user", user))

    # Groups
    for group in raw["GroupDetailList"]:
        snapshot["principals"].append(normalize_principal("group", group))

    # Roles
    for role in raw["RoleDetailList"]:
        snapshot["principals"].append(normalize_principal("role", role))

    # Managed policies (local + AWS managed)
    for policy in raw["Policies"]:
        normalized = normalize_managed_policy(policy)
        if normalized:
            snapshot["managed_policies"].append(normalized)

    logger.info(
        "Snapshot built: %d principals, %d managed policies",
        len(snapshot["principals"]),
        len(snapshot["managed_policies"]),
    )
    return snapshot


def ingest(output_path: Path = DEFAULT_OUTPUT) -> dict:
    """
    Main ingestion function. Pulls IAM data, normalizes it, writes JSON cache.

    Returns the snapshot dict (so callers can chain directly to graph_builder).
    """
    iam = boto3.client("iam", region_name=REGION)
    sts = boto3.client("sts", region_name=REGION)

    try:
        account_id = sts.get_caller_identity()["Account"]
    except ClientError as e:
        logger.error("Could not get account identity: %s", e)
        logger.error("Ensure AWS credentials are configured (aws configure or IAM role).")
        sys.exit(1)

    logger.info("Ingesting IAM data for account %s", account_id)

    raw = fetch_account_authorization_details(iam)
    snapshot = build_snapshot(raw, account_id)

    # Write cache
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, default=str)

    logger.info("Snapshot written to %s", output_path)
    return snapshot


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ingest.py",
        description="Pull all IAM policies from the AWS account and write a JSON snapshot.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output file path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    ingest(Path(args.output))


if __name__ == "__main__":
    main()
