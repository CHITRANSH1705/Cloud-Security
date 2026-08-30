"""
iam_graph/patterns.py

Known AWS Privilege Escalation Chain Definitions

Encodes 6 escalation chains from the Rhino Security Labs catalog as Cypher
graph queries against the Neo4j IAM permission graph.

Source: "AWS IAM Privilege Escalation – Methods and Mitigation"
        Rhino Security Labs (2019, updated)
        https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

Each chain is represented as:
    - A Cypher query that returns matching principals
    - A human-readable description of the attack path
    - The MITRE ATT&CK technique it maps to

IMPORTANT: These patterns flag combinations of permissions, not individual
risky permissions. A principal with ONLY iam:PassRole is not flagged. Only the
combination iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction is.

Usage:
    python iam_graph/patterns.py --run-all
    python iam_graph/patterns.py --chain RSL-01
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable

# ─── Conditional import ──────────────────────────────────────────────────────
try:
    from common.attack_mapping import tag_finding, TECHNIQUES
except ImportError:
    from attack_mapping import tag_finding, TECHNIQUES  # type: ignore[no-redef]

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

NEO4J_URI      = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER     = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "killswitch-local-dev")


# ─────────────────────────────────────────────────────────────────────────────
# Escalation Chain Definitions
# ─────────────────────────────────────────────────────────────────────────────

ESCALATION_CHAINS: dict[str, dict[str, Any]] = {

    "RSL-01": {
        "name": "Lambda Code Execution via PassRole",
        "description": (
            "Principal has iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction. "
            "Attack: Create a Lambda function with a high-privileged role, invoke it to "
            "execute arbitrary code under that role's permissions."
        ),
        "technique_key": "PRIV_ESC_LAMBDA",
        "required_actions": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
        "cypher": """
            MATCH (p:Principal)-[:CAN_PERFORM {effect: 'Allow'}]->(a1:Action {name: 'iam:PassRole'})
            MATCH (p)-[:CAN_PERFORM {effect: 'Allow'}]->(a2:Action {name: 'lambda:CreateFunction'})
            MATCH (p)-[:CAN_PERFORM {effect: 'Allow'}]->(a3:Action {name: 'lambda:InvokeFunction'})
            RETURN DISTINCT
                p.arn         AS principal_arn,
                p.name        AS principal_name,
                p.type        AS principal_type,
                'RSL-01'      AS chain_id,
                'iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction' AS matched_actions
        """,
    },

    "RSL-02": {
        "name": "EC2 Instance Launch via PassRole",
        "description": (
            "Principal has iam:PassRole + ec2:RunInstances. "
            "Attack: Launch an EC2 instance with a high-privileged instance profile; "
            "the instance metadata service (IMDS) exposes the role's credentials."
        ),
        "technique_key": "PRIV_ESC_EC2",
        "required_actions": [
            "iam:PassRole",
            "ec2:RunInstances",
        ],
        "cypher": """
            MATCH (p:Principal)-[:CAN_PERFORM {effect: 'Allow'}]->(a1:Action {name: 'iam:PassRole'})
            MATCH (p)-[:CAN_PERFORM {effect: 'Allow'}]->(a2:Action {name: 'ec2:RunInstances'})
            RETURN DISTINCT
                p.arn         AS principal_arn,
                p.name        AS principal_name,
                p.type        AS principal_type,
                'RSL-02'      AS chain_id,
                'iam:PassRole + ec2:RunInstances' AS matched_actions
        """,
    },

    "RSL-03": {
        "name": "Policy Version Replacement",
        "description": (
            "Principal has iam:CreatePolicyVersion. "
            "Attack: Create a new version of any managed policy that grants AdministratorAccess, "
            "then set it as the default version."
        ),
        "technique_key": "PRIV_ESC_POLICY_VERSION",
        "required_actions": [
            "iam:CreatePolicyVersion",
        ],
        "cypher": """
            MATCH (p:Principal)-[:CAN_PERFORM {effect: 'Allow'}]->(a:Action {name: 'iam:CreatePolicyVersion'})
            RETURN DISTINCT
                p.arn         AS principal_arn,
                p.name        AS principal_name,
                p.type        AS principal_type,
                'RSL-03'      AS chain_id,
                'iam:CreatePolicyVersion' AS matched_actions
        """,
    },

    "RSL-04": {
        "name": "Set Default Policy Version",
        "description": (
            "Principal has iam:SetDefaultPolicyVersion. "
            "Attack: If a previously created permissive policy version exists (non-default), "
            "promote it to default — effectively granting escalated permissions without "
            "creating new resources."
        ),
        "technique_key": "PRIV_ESC_SET_DEFAULT_VERSION",
        "required_actions": [
            "iam:SetDefaultPolicyVersion",
        ],
        "cypher": """
            MATCH (p:Principal)-[:CAN_PERFORM {effect: 'Allow'}]->(a:Action {name: 'iam:SetDefaultPolicyVersion'})
            RETURN DISTINCT
                p.arn         AS principal_arn,
                p.name        AS principal_name,
                p.type        AS principal_type,
                'RSL-04'      AS chain_id,
                'iam:SetDefaultPolicyVersion' AS matched_actions
        """,
    },

    "RSL-05": {
        "name": "Self-Policy Attachment",
        "description": (
            "Principal has iam:AttachUserPolicy (or iam:AttachRolePolicy) scoped to * or self. "
            "Attack: Attach AdministratorAccess or any admin-equivalent policy to themselves."
        ),
        "technique_key": "PRIV_ESC_ATTACH_SELF_POLICY",
        "required_actions": [
            "iam:AttachUserPolicy",
        ],
        "cypher": """
            MATCH (p:Principal)-[:CAN_PERFORM {effect: 'Allow'}]->(a:Action)
            WHERE a.name IN ['iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy', 'iam:*', '*']
            RETURN DISTINCT
                p.arn         AS principal_arn,
                p.name        AS principal_name,
                p.type        AS principal_type,
                'RSL-05'      AS chain_id,
                a.name        AS matched_actions
        """,
    },

    "RSL-06": {
        "name": "Unconstrained AssumeRole on Admin-Equivalent Role",
        "description": (
            "A role's trust policy allows sts:AssumeRole without a Condition block, "
            "AND that role has admin-equivalent actions. "
            "Attack: Any principal in the trust boundary can assume this role and gain its permissions."
        ),
        "technique_key": "PRIV_ESC_ASSUME_ADMIN_ROLE",
        "required_actions": [
            "sts:AssumeRole",
        ],
        "cypher": """
            MATCH (trustee:Principal)-[c:CAN_ASSUME {has_condition: false}]->(role:Principal)
            MATCH (role)-[:CAN_PERFORM {effect: 'Allow'}]->(a:Action)
            WHERE a.name IN ['*', 'iam:*', 'iam:PassRole', 'iam:CreatePolicyVersion']
               OR a.is_high_privilege = true
            RETURN DISTINCT
                trustee.arn   AS principal_arn,
                trustee.name  AS principal_name,
                trustee.type  AS principal_type,
                'RSL-06'      AS chain_id,
                'sts:AssumeRole (no Condition) + high-priv role: ' + role.arn AS matched_actions
        """,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Pattern runner
# ─────────────────────────────────────────────────────────────────────────────

def get_driver() -> Driver:
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        return driver
    except ServiceUnavailable as e:
        logger.error("Cannot connect to Neo4j: %s — is 'docker compose up -d' running?", e)
        sys.exit(1)


def run_chain(driver: Driver, chain_id: str) -> list[dict[str, Any]]:
    """
    Execute a single escalation chain Cypher query.
    Returns a list of finding dicts (one per matching principal).
    """
    chain = ESCALATION_CHAINS.get(chain_id)
    if not chain:
        raise ValueError(f"Unknown chain ID: {chain_id}. Valid: {list(ESCALATION_CHAINS.keys())}")

    findings: list[dict[str, Any]] = []

    with driver.session() as session:
        results = session.run(chain["cypher"])
        for record in results:
            finding = {
                "chain_id":        chain_id,
                "chain_name":      chain["name"],
                "chain_description": chain["description"],
                "principal_arn":   record["principal_arn"],
                "principal_name":  record["principal_name"],
                "principal_type":  record.get("principal_type", ""),
                "matched_actions": record["matched_actions"],
                "detected_at":     datetime.now(timezone.utc).isoformat(),
                "exploit_verified": False,  # Phase 4 would set this to True if confirmed
                "note": "detected, not exploit-verified (Phase 4 not built)",
            }
            finding = tag_finding(finding, chain["technique_key"])
            findings.append(finding)

    if findings:
        logger.warning(
            "Chain %s (%s): %d principal(s) matched",
            chain_id, chain["name"], len(findings),
        )
    else:
        logger.info("Chain %s: no matches found.", chain_id)

    return findings


def run_all_chains(driver: Driver) -> dict[str, list[dict]]:
    """Run all defined chains and return a dict of chain_id → findings list."""
    all_findings: dict[str, list[dict]] = {}
    for chain_id in ESCALATION_CHAINS:
        all_findings[chain_id] = run_chain(driver, chain_id)
    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="patterns.py",
        description="Run privilege escalation chain detection against the Neo4j IAM graph.",
    )
    parser.add_argument(
        "--run-all",
        action="store_true",
        help="Run all defined escalation chains.",
    )
    parser.add_argument(
        "--chain",
        metavar="CHAIN_ID",
        help=f"Run a specific chain. Options: {', '.join(ESCALATION_CHAINS.keys())}",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write findings JSON to this file (default: print to stdout)",
    )
    args = parser.parse_args()

    if not args.run_all and not args.chain:
        parser.print_help()
        sys.exit(1)

    driver = get_driver()
    try:
        if args.run_all:
            results = run_all_chains(driver)
            output = {
                "meta": {
                    "run_at":      datetime.now(timezone.utc).isoformat(),
                    "chains_run":  list(ESCALATION_CHAINS.keys()),
                    "total_findings": sum(len(v) for v in results.values()),
                },
                "findings_by_chain": results,
            }
        else:
            findings = run_chain(driver, args.chain)
            output = {
                "meta": {
                    "run_at":   datetime.now(timezone.utc).isoformat(),
                    "chain_id": args.chain,
                    "total_findings": len(findings),
                },
                "findings": findings,
            }

        output_str = json.dumps(output, indent=2, default=str)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
            logger.info("Findings written to %s", args.output)
        else:
            print(output_str)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
