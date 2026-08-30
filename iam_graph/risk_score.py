"""
iam_graph/risk_score.py

Per-Principal Risk Scorer

For each principal flagged by patterns.py, computes a numeric risk score (0–100)
from two components:

    Path Score (0–50):
        Measures how many hops separate this principal from an admin-equivalent
        action in the graph. Shorter path = greater privilege proximity = worse.
        Formula: 50 / shortest_path_length  (capped at 50, min path = 1)

    Blast Radius Score (0–50):
        Counts distinct AWS resources reachable if the escalation succeeds.
        More reachable resources = larger blast radius = worse.
        Formula: min(50, distinct_reachable_resources * 5)

    Total Risk Score = path_score + blast_radius_score  (0–100)

After scoring, the score is:
    1. Written back onto the :Principal node in Neo4j (p.risk_score)
    2. Written to DynamoDB table killswitch-baselines so that revoke.py
       in Phase 2 can read it without needing a Neo4j connection from Lambda.

Output: reports/iam_risk_report_<timestamp>.json

Usage:
    python iam_graph/risk_score.py
    python iam_graph/risk_score.py --output custom_report.json
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
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable

# ─── Conditional import ──────────────────────────────────────────────────────
try:
    from iam_graph.patterns import ESCALATION_CHAINS, run_all_chains, get_driver as _get_neo4j_driver
except ImportError:
    from patterns import ESCALATION_CHAINS, run_all_chains, get_driver as _get_neo4j_driver  # type: ignore[no-redef]

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

REGION          = os.environ.get("AWS_REGION", "us-east-1")
BASELINE_TABLE  = os.environ.get("BASELINE_TABLE", "killswitch-baselines")
NEO4J_URI       = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER      = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD  = os.environ.get("NEO4J_PASSWORD", "killswitch-local-dev")

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Admin-equivalent actions for path scoring
ADMIN_ACTION_NAMES = [
    "iam:*", "*",
    "iam:PassRole", "iam:CreatePolicyVersion", "iam:AttachUserPolicy",
    "lambda:CreateFunction", "ec2:RunInstances",
]


# ─────────────────────────────────────────────────────────────────────────────
# Path length scoring
# ─────────────────────────────────────────────────────────────────────────────

def compute_shortest_path_to_admin(driver: Driver, principal_arn: str) -> int | None:
    """
    Find the shortest path (hop count) from this principal to any admin-equivalent
    Action node in the graph.

    The path can traverse:
        - CAN_PERFORM edges (direct permission grants)
        - CAN_ASSUME edges (role assumption chains)
        - MEMBER_OF edges (group memberships)

    Returns the shortest path length (1 = has direct admin permission),
    or None if no path exists to any admin-equivalent action.
    """
    query = """
        MATCH path = shortestPath(
            (p:Principal {arn: $principal_arn})-[:CAN_PERFORM|CAN_ASSUME|MEMBER_OF*1..8]->(target)
        )
        WHERE (
            (target:Action AND target.name IN $admin_actions)
            OR
            (target:Action AND target.is_high_privilege = true)
        )
        RETURN length(path) AS path_length
        ORDER BY path_length ASC
        LIMIT 1
    """
    with driver.session() as session:
        result = session.run(query, principal_arn=principal_arn, admin_actions=ADMIN_ACTION_NAMES)
        record = result.single()
        if record:
            return int(record["path_length"])
        return None


def path_score(path_length: int | None) -> int:
    """
    Convert shortest path length to a 0–50 score.

    path_length=1  → 50 (direct admin access, worst)
    path_length=2  → 25
    path_length=4  → 12
    path_length=None → 0 (no escalation path found)
    """
    if path_length is None or path_length <= 0:
        return 0
    return min(50, round(50 / path_length))


# ─────────────────────────────────────────────────────────────────────────────
# Blast radius scoring
# ─────────────────────────────────────────────────────────────────────────────

def compute_blast_radius(driver: Driver, principal_arn: str) -> int:
    """
    Count distinct resources reachable from this principal through any path
    (direct permissions + role assumption + group membership).

    This measures the potential damage scope if the escalation succeeds.
    """
    query = """
        MATCH (p:Principal {arn: $principal_arn})
              -[:CAN_PERFORM|CAN_ASSUME|MEMBER_OF*1..6]->()
              -[:CAN_PERFORM|ON*0..2]->(r:Resource)
        RETURN count(DISTINCT r.arn_pattern) AS resource_count
    """
    with driver.session() as session:
        result = session.run(query, principal_arn=principal_arn)
        record = result.single()
        return int(record["resource_count"]) if record else 0


def blast_radius_score(resource_count: int) -> int:
    """
    Convert resource count to a 0–50 score.

    0 resources  → 0
    1 resource   → 5
    10 resources → 50 (capped)
    """
    return min(50, resource_count * 5)


# ─────────────────────────────────────────────────────────────────────────────
# Write scores back to Neo4j
# ─────────────────────────────────────────────────────────────────────────────

def write_score_to_neo4j(driver: Driver, principal_arn: str, score: int) -> None:
    """Write risk_score property onto the Principal node in Neo4j."""
    with driver.session() as session:
        session.run(
            "MATCH (p:Principal {arn: $arn}) SET p.risk_score = $score",
            arn=principal_arn,
            score=score,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Write scores to DynamoDB
# ─────────────────────────────────────────────────────────────────────────────

def write_score_to_dynamodb(principal_arn: str, score: int) -> None:
    """
    Upsert risk_score into DynamoDB killswitch-baselines table.

    This allows revoke.py (running in Lambda) to read the risk score without
    needing a direct connection to Neo4j.
    """
    ddb = boto3.client("dynamodb", region_name=REGION)
    try:
        ddb.update_item(
            TableName=BASELINE_TABLE,
            Key={"principal_arn": {"S": principal_arn}},
            UpdateExpression="SET risk_score = :score, risk_scored_at = :ts",
            ExpressionAttributeValues={
                ":score": {"N": str(score)},
                ":ts":    {"S": datetime.now(timezone.utc).isoformat()},
            },
        )
        logger.debug("DynamoDB: risk_score=%d written for %s", score, principal_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            # Table doesn't exist yet (Phase 1 not run) — skip silently
            logger.warning("DynamoDB table %s not found — skipping DDB write. "
                           "Run infra/setup.py first.", BASELINE_TABLE)
        else:
            logger.error("DynamoDB update_item failed for %s: %s", principal_arn, e)


# ─────────────────────────────────────────────────────────────────────────────
# Main scoring pipeline
# ─────────────────────────────────────────────────────────────────────────────

def score_all_principals(driver: Driver) -> list[dict[str, Any]]:
    """
    1. Run all escalation chain patterns to get flagged principals
    2. For each unique flagged principal:
       a. Compute shortest path to admin action
       b. Compute blast radius
       c. Compute total risk score
       d. Write back to Neo4j + DynamoDB
    3. Return list of scored principal records

    Deduplicates principals that appear in multiple chains (uses max score
    across all chains for that principal).
    """
    logger.info("Running escalation chain detection...")
    all_chain_findings = run_all_chains(driver)

    # Deduplicate: one record per principal_arn (may appear in multiple chains)
    principal_findings: dict[str, dict[str, Any]] = {}
    for chain_id, findings in all_chain_findings.items():
        for finding in findings:
            arn = finding["principal_arn"]
            if arn not in principal_findings:
                principal_findings[arn] = {
                    "principal_arn":  arn,
                    "principal_name": finding["principal_name"],
                    "principal_type": finding.get("principal_type", ""),
                    "matched_chains": [],
                    "matched_actions": [],
                }
            principal_findings[arn]["matched_chains"].append(chain_id)
            principal_findings[arn]["matched_actions"].append(finding["matched_actions"])

    logger.info("Scoring %d unique flagged principals...", len(principal_findings))

    scored: list[dict[str, Any]] = []

    for arn, record in principal_findings.items():
        path_len      = compute_shortest_path_to_admin(driver, arn)
        resource_cnt  = compute_blast_radius(driver, arn)
        p_score       = path_score(path_len)
        b_score       = blast_radius_score(resource_cnt)
        total_score   = p_score + b_score

        record.update({
            "path_to_admin_length":  path_len,
            "blast_radius_resources": resource_cnt,
            "path_score":            p_score,
            "blast_radius_score":    b_score,
            "total_risk_score":      total_score,
            "risk_tier":             _score_to_tier(total_score),
            "scored_at":             datetime.now(timezone.utc).isoformat(),
            "exploit_verified":      False,
            "note":                  "detected, not exploit-verified (Phase 4 not built)",
        })

        # Write back
        write_score_to_neo4j(driver, arn, total_score)
        write_score_to_dynamodb(arn, total_score)

        scored.append(record)

        logger.info(
            "Principal %s: path=%s blast_radius=%d → score=%d (%s)",
            record["principal_name"], path_len, resource_cnt, total_score, record["risk_tier"],
        )

    # Sort by score descending (highest risk first)
    scored.sort(key=lambda x: x["total_risk_score"], reverse=True)
    return scored


def _score_to_tier(score: int) -> str:
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="risk_score.py",
        description=(
            "Score each flagged IAM principal by privilege-escalation path length "
            "and blast radius. Writes scores to Neo4j and DynamoDB."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write risk report JSON to this path (default: reports/iam_risk_report_<ts>.json)",
    )
    args = parser.parse_args()

    driver = _get_neo4j_driver()
    try:
        scored = score_all_principals(driver)
    finally:
        driver.close()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = Path(args.output) if args.output else REPORTS_DIR / f"iam_risk_report_{ts}.json"

    report = {
        "meta": {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "total_principals_flagged": len(scored),
            "high_risk":  sum(1 for s in scored if s["risk_tier"] == "HIGH"),
            "medium_risk": sum(1 for s in scored if s["risk_tier"] == "MEDIUM"),
            "low_risk":   sum(1 for s in scored if s["risk_tier"] == "LOW"),
            "exploit_verification": "NOT PERFORMED — Phase 4 not built",
        },
        "principals": scored,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("Risk report written to %s", output_path)

    # Print summary to stdout
    print(f"\n{'─'*60}")
    print(f"IAM Risk Report — {ts}")
    print(f"{'─'*60}")
    print(f"Flagged principals: {len(scored)}")
    for record in scored:
        print(
            f"  [{record['risk_tier']:6}] {record['principal_name']:40} "
            f"score={record['total_risk_score']:3d}  "
            f"chains={','.join(record['matched_chains'])}"
        )
    print(f"\nFull report: {output_path}")
    print(f"\nNOTE: All findings are 'detected, not exploit-verified' — "
          f"Phase 4 (escalation_test.py) was not built.")


if __name__ == "__main__":
    main()
