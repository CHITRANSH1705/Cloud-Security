"""
iam_graph/graph_builder.py

Neo4j IAM Permission Graph Builder

Reads the iam_graph/cache/iam_snapshot.json produced by ingest.py and builds
a Neo4j property graph with the following schema:

NODES
─────
(:Principal {arn, name, type, path, risk_score})
    type ∈ {"user", "group", "role"}
    risk_score is written later by risk_score.py

(:Action {name})
    e.g. "s3:PutObject", "iam:PassRole", "lambda:CreateFunction"
    Wildcard actions like "s3:*" are stored as-is; pattern.py handles expansion.

(:Resource {arn_pattern})
    e.g. "arn:aws:s3:::*", "*", "arn:aws:s3:::killswitch-test-123/*"

(:ManagedPolicy {arn, name, is_aws_managed})
    Represents a managed policy document (separate from the principal it's attached to).

EDGES
─────
(:Principal)-[:CAN_PERFORM {via_policy, effect, condition}]->(:Action)-[:ON]->(:Resource)
    Represents a policy statement granting (or denying) an action on a resource.

(:Principal)-[:MEMBER_OF]->(:Principal)
    User → Group membership.

(:Principal)-[:CAN_ASSUME {condition}]->(:Principal)
    Role trust policy — who can sts:AssumeRole into this role.

(:Principal)-[:HAS_POLICY {policy_type}]->(:ManagedPolicy)
    Which managed policies are attached to a principal.

Usage:
    python iam_graph/graph_builder.py --clear   # wipe graph and rebuild from scratch
    python iam_graph/graph_builder.py --update  # upsert only (preserves existing risk_scores)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

from dotenv import load_dotenv
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

NEO4J_URI      = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER     = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "killswitch-local-dev")

DEFAULT_SNAPSHOT = Path(__file__).parent / "cache" / "iam_snapshot.json"

# High-privilege action patterns — used to mark nodes as "admin-equivalent"
ADMIN_ACTIONS = {
    "*",
    "iam:*",
    "sts:AssumeRole",
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
}


# ─────────────────────────────────────────────────────────────────────────────
# Neo4j connection
# ─────────────────────────────────────────────────────────────────────────────

def get_driver() -> Driver:
    """Create and verify a Neo4j driver connection."""
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", NEO4J_URI)
        return driver
    except ServiceUnavailable as e:
        logger.error(
            "Cannot connect to Neo4j at %s: %s\n"
            "Is the Neo4j container running? Try: docker compose up -d",
            NEO4J_URI, e,
        )
        sys.exit(1)
    except Exception as e:
        logger.error("Neo4j connection error: %s", e)
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Schema / constraints
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_QUERIES = [
    # Uniqueness constraints (also create indexes)
    "CREATE CONSTRAINT principal_arn IF NOT EXISTS FOR (p:Principal) REQUIRE p.arn IS UNIQUE",
    "CREATE CONSTRAINT action_name   IF NOT EXISTS FOR (a:Action)    REQUIRE a.name IS UNIQUE",
    "CREATE CONSTRAINT resource_arn  IF NOT EXISTS FOR (r:Resource)  REQUIRE r.arn_pattern IS UNIQUE",
    "CREATE CONSTRAINT policy_arn    IF NOT EXISTS FOR (m:ManagedPolicy) REQUIRE m.arn IS UNIQUE",
]


def ensure_schema(driver: Driver) -> None:
    """Create uniqueness constraints and indexes."""
    with driver.session() as session:
        for q in SCHEMA_QUERIES:
            try:
                session.run(q)
            except Exception as e:
                logger.debug("Schema query skipped (may already exist): %s — %s", q[:60], e)
    logger.info("Schema constraints verified.")


def clear_graph(driver: Driver) -> None:
    """Delete all nodes and relationships. Use before a full rebuild."""
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    logger.warning("Graph cleared — all nodes and relationships deleted.")


# ─────────────────────────────────────────────────────────────────────────────
# Graph construction helpers
# ─────────────────────────────────────────────────────────────────────────────

def upsert_principal(session: Any, principal: dict) -> None:
    """MERGE a Principal node (upsert — creates if not exists, updates if exists)."""
    session.run(
        """
        MERGE (p:Principal {arn: $arn})
        SET p.name          = $name,
            p.type          = $type,
            p.path          = $path
        """,
        arn=principal["arn"],
        name=principal["name"],
        type=principal["principal_type"],
        path=principal.get("path", "/"),
    )


def upsert_action(session: Any, action_name: str) -> None:
    """MERGE an Action node."""
    is_high_priv = action_name in ADMIN_ACTIONS or action_name.endswith(":*")
    session.run(
        """
        MERGE (a:Action {name: $name})
        SET a.is_high_privilege = $is_high_priv
        """,
        name=action_name,
        is_high_priv=is_high_priv,
    )


def upsert_resource(session: Any, arn_pattern: str) -> None:
    """MERGE a Resource node."""
    is_wildcard = "*" in arn_pattern
    session.run(
        """
        MERGE (r:Resource {arn_pattern: $arn_pattern})
        SET r.is_wildcard = $is_wildcard
        """,
        arn_pattern=arn_pattern,
        is_wildcard=is_wildcard,
    )


def create_can_perform_edge(
    session: Any,
    principal_arn: str,
    action_name: str,
    resource_arn: str,
    effect: str,
    via_policy: str,
) -> None:
    """
    Create (:Principal)-[:CAN_PERFORM {effect}]->(:Action)-[:ON]->(:Resource)

    Note: We create the intermediate Action→Resource edge too.
    The effect field stores "Allow" or "Deny" so patterns.py can filter.
    """
    session.run(
        """
        MATCH (p:Principal {arn: $principal_arn})
        MERGE (a:Action {name: $action_name})
        MERGE (r:Resource {arn_pattern: $resource_arn})
        MERGE (p)-[:CAN_PERFORM {effect: $effect, via_policy: $via_policy}]->(a)
        MERGE (a)-[:ON]->(r)
        """,
        principal_arn=principal_arn,
        action_name=action_name,
        resource_arn=resource_arn,
        effect=effect,
        via_policy=via_policy,
    )


def create_member_of_edge(session: Any, user_arn: str, group_arn: str) -> None:
    """Create (:Principal {type:user})-[:MEMBER_OF]->(:Principal {type:group})"""
    session.run(
        """
        MATCH (u:Principal {arn: $user_arn})
        MATCH (g:Principal {arn: $group_arn})
        MERGE (u)-[:MEMBER_OF]->(g)
        """,
        user_arn=user_arn,
        group_arn=group_arn,
    )


def create_can_assume_edge(
    session: Any,
    trustee_arn: str,
    role_arn: str,
    has_condition: bool,
) -> None:
    """
    Create (:Principal {trustee})-[:CAN_ASSUME {has_condition}]->(:Principal {role})

    has_condition=False means the trust policy has NO Condition block — this is
    the RSL-06 pattern: unconstrained assume-role escalation.
    """
    session.run(
        """
        MERGE (t:Principal {arn: $trustee_arn})
        ON CREATE SET t.type = 'inferred', t.name = $trustee_arn
        MATCH (r:Principal {arn: $role_arn})
        MERGE (t)-[:CAN_ASSUME {has_condition: $has_condition}]->(r)
        """,
        trustee_arn=trustee_arn,
        role_arn=role_arn,
        has_condition=has_condition,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Policy document → graph edges
# ─────────────────────────────────────────────────────────────────────────────

def expand_policy_document(
    session: Any,
    principal_arn: str,
    policy_name: str,
    doc: dict,
) -> None:
    """
    Parse a policy document and create Action/Resource nodes + CAN_PERFORM edges.

    Handles both single-statement and multi-statement policies.
    Handles both string and list formats for Action and Resource.
    """
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "Allow")
        actions_raw = stmt.get("Action", [])
        resources_raw = stmt.get("Resource", [])
        not_action = stmt.get("NotAction")  # rare but exists

        if not_action:
            # NotAction is complex — record it as a note but don't expand
            logger.debug("Skipping NotAction statement in policy %s", policy_name)
            continue

        actions = [actions_raw] if isinstance(actions_raw, str) else actions_raw
        resources = [resources_raw] if isinstance(resources_raw, str) else resources_raw

        for action in actions:
            if not isinstance(action, str):
                continue
            upsert_action(session, action)
            for resource in resources:
                if not isinstance(resource, str):
                    continue
                upsert_resource(session, resource)
                create_can_perform_edge(
                    session,
                    principal_arn=principal_arn,
                    action_name=action,
                    resource_arn=resource,
                    effect=effect,
                    via_policy=policy_name,
                )


# ─────────────────────────────────────────────────────────────────────────────
# Trust policy → CAN_ASSUME edges
# ─────────────────────────────────────────────────────────────────────────────

def expand_trust_policy(session: Any, role_arn: str, trust_doc: dict) -> None:
    """
    Parse a role trust policy and create CAN_ASSUME edges.

    Trust policy statements have Principal (not Action), e.g.:
        { "Effect":"Allow", "Principal": {"Service":"lambda.amazonaws.com"},
          "Action": "sts:AssumeRole" }
    """
    statements = trust_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        if stmt.get("Action") not in ("sts:AssumeRole", ["sts:AssumeRole"]):
            continue

        principal_block = stmt.get("Principal", {})
        has_condition   = bool(stmt.get("Condition"))

        # Principal block can be "*" or {"Service": [...]} or {"AWS": [...]}
        if principal_block == "*":
            trustee_arns = ["*"]
        elif isinstance(principal_block, str):
            trustee_arns = [principal_block]
        elif isinstance(principal_block, dict):
            trustee_arns = []
            for kind, val in principal_block.items():
                if isinstance(val, str):
                    trustee_arns.append(val)
                elif isinstance(val, list):
                    trustee_arns.extend(val)
        else:
            trustee_arns = []

        for trustee_arn in trustee_arns:
            create_can_assume_edge(session, trustee_arn, role_arn, has_condition)


# ─────────────────────────────────────────────────────────────────────────────
# Managed policy resolution
# ─────────────────────────────────────────────────────────────────────────────

def build_managed_policy_index(managed_policies: list[dict]) -> dict[str, dict]:
    """Build an ARN → policy doc lookup for managed policies."""
    return {mp["arn"]: mp for mp in managed_policies if mp.get("arn")}


# ─────────────────────────────────────────────────────────────────────────────
# Main graph build
# ─────────────────────────────────────────────────────────────────────────────

def build_graph(driver: Driver, snapshot: dict) -> None:
    """
    Translate the IAM snapshot into Neo4j nodes and relationships.

    Processing order:
    1. Create all Principal nodes first (so MERGE can find them for edges)
    2. Create group MEMBER_OF edges
    3. Expand inline policies → Action/Resource nodes + CAN_PERFORM edges
    4. Resolve attached managed policies → same expansion
    5. Expand role trust policies → CAN_ASSUME edges
    """
    principals       = snapshot.get("principals", [])
    managed_policies = snapshot.get("managed_policies", [])
    policy_index     = build_managed_policy_index(managed_policies)

    # ── Build a group ARN lookup: name → arn ────────────────────────────────
    group_arn_by_name = {
        p["name"]: p["arn"]
        for p in principals
        if p["principal_type"] == "group"
    }

    total = len(principals)
    logger.info("Building graph for %d principals...", total)

    with driver.session() as session:

        # ── 1. Upsert all principals ─────────────────────────────────────────
        for principal in principals:
            upsert_principal(session, principal)
        logger.info("Upserted %d Principal nodes.", total)

        # ── 2. Group membership ───────────────────────────────────────────────
        for principal in principals:
            if principal["principal_type"] == "user":
                for group_name in principal.get("groups", []):
                    group_arn = group_arn_by_name.get(group_name)
                    if group_arn:
                        create_member_of_edge(session, principal["arn"], group_arn)

        # ── 3 & 4. Inline + attached managed policies ─────────────────────────
        for principal in principals:
            arn = principal["arn"]

            # Inline policies
            for ip in principal.get("inline_policies", []):
                doc = ip.get("policy_document")
                if doc:
                    expand_policy_document(session, arn, ip.get("policy_name", "inline"), doc)

            # Attached managed policies — resolve full document from index
            for ap in principal.get("attached_policies", []):
                policy_arn  = ap.get("policy_arn", "")
                policy_name = ap.get("policy_name", "")
                managed = policy_index.get(policy_arn)
                if managed and managed.get("document"):
                    expand_policy_document(session, arn, policy_name, managed["document"])
                else:
                    logger.debug("Managed policy document not found for ARN: %s", policy_arn)

            # ── 5. Trust policies (roles only) ────────────────────────────────
            if principal["principal_type"] == "role" and principal.get("trust_policy"):
                expand_trust_policy(session, arn, principal["trust_policy"])

        logger.info("Graph build complete.")

    # ── Summary query ─────────────────────────────────────────────────────────
    with driver.session() as session:
        counts = session.run(
            """
            MATCH (p:Principal) WITH count(p) AS principals
            MATCH (a:Action)    WITH principals, count(a) AS actions
            MATCH (r:Resource)  WITH principals, actions, count(r) AS resources
            RETURN principals, actions, resources
            """
        ).single()
        if counts:
            logger.info(
                "Graph summary: %d principals, %d actions, %d resources",
                counts["principals"], counts["actions"], counts["resources"],
            )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="graph_builder.py",
        description="Build Neo4j IAM permission graph from IAM snapshot.",
    )
    parser.add_argument(
        "--snapshot",
        default=str(DEFAULT_SNAPSHOT),
        help=f"Input snapshot JSON (default: {DEFAULT_SNAPSHOT})",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Wipe the entire graph before rebuilding (full rebuild mode)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Upsert only — preserves existing risk_score values (incremental mode)",
    )
    args = parser.parse_args()

    if not Path(args.snapshot).exists():
        logger.error("Snapshot file not found: %s — run ingest.py first.", args.snapshot)
        sys.exit(1)

    with open(args.snapshot, encoding="utf-8") as f:
        snapshot = json.load(f)

    driver = get_driver()
    try:
        ensure_schema(driver)
        if args.clear:
            clear_graph(driver)
        build_graph(driver, snapshot)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
