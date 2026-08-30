"""
infra/teardown.py

AWS Resource Cleanup — Destroy all resources created by setup.py

⚠  This permanently deletes all Kill-Switch resources from your AWS account.
   Run this when you are done with the demo.

Usage:
    python infra/teardown.py           # Dry-run (shows what would be deleted)
    python infra/teardown.py --confirm # Actually delete resources
"""

from __future__ import annotations

import argparse
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

REGION = os.environ.get("AWS_REGION", "us-east-1")

RESOURCE_NAMES = {
    "lambda_function":  "killswitch-detector",
    "lambda_role":      "killswitch-lambda-role",
    "lambda_policy":    "killswitch-lambda-exec-policy",
    "eventbridge_rule": "killswitch-s3-events",
    "baseline_table":   "killswitch-baselines",
    "trail_name":       "killswitch-trail",
    "attacker_user":    "killswitch-attacker",
    "sns_topic":        "killswitch-alerts",
    "log_group":        "/killswitch/remediations",
}


def get_account_id() -> str:
    return boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]


def _safe_delete(name: str, fn: Any) -> None:
    try:
        fn()
        logger.info("Deleted: %s", name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in (
            "NoSuchEntity", "ResourceNotFoundException",
            "ResourceNotFoundFault", "NoSuchBucket",
            "TrailNotFoundException",
        ):
            logger.info("Already deleted (or never existed): %s", name)
        else:
            logger.warning("Could not delete %s: %s", name, e)


def delete_all_objects(s3: Any, bucket: str) -> None:
    """Empty a versioned bucket before deletion."""
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objects = []
            for version in page.get("Versions", []):
                objects.append({"Key": version["Key"], "VersionId": version["VersionId"]})
            for marker in page.get("DeleteMarkers", []):
                objects.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    except ClientError:
        pass


def teardown(confirm: bool = False) -> None:
    account_id = get_account_id()
    test_bucket = f"killswitch-test-{account_id}"
    log_bucket  = f"killswitch-cloudtrail-{account_id}"
    sns_arn     = f"arn:aws:sns:{REGION}:{account_id}:{RESOURCE_NAMES['sns_topic']}"

    resources_to_delete = [
        f"Lambda function:   {RESOURCE_NAMES['lambda_function']}",
        f"EventBridge rule:  {RESOURCE_NAMES['eventbridge_rule']}",
        f"CloudTrail trail:  {RESOURCE_NAMES['trail_name']}",
        f"DynamoDB table:    {RESOURCE_NAMES['baseline_table']}",
        f"IAM role:          {RESOURCE_NAMES['lambda_role']}",
        f"IAM user:          {RESOURCE_NAMES['attacker_user']}",
        f"SNS topic:         {sns_arn}",
        f"S3 bucket:         {test_bucket}",
        f"S3 bucket:         {log_bucket}",
        f"CloudWatch group:  {RESOURCE_NAMES['log_group']}",
    ]

    print("\n⚠  The following AWS resources will be PERMANENTLY DELETED:\n")
    for r in resources_to_delete:
        print(f"   {r}")
    print()

    if not confirm:
        print("Dry run — nothing deleted. Add --confirm to proceed.\n")
        return

    clients = {
        "s3":         boto3.client("s3",         region_name=REGION),
        "iam":        boto3.client("iam",         region_name=REGION),
        "dynamodb":   boto3.client("dynamodb",    region_name=REGION),
        "cloudtrail": boto3.client("cloudtrail",  region_name=REGION),
        "lambda_":    boto3.client("lambda",      region_name=REGION),
        "events":     boto3.client("events",      region_name=REGION),
        "sns":        boto3.client("sns",         region_name=REGION),
        "logs":       boto3.client("logs",        region_name=REGION),
    }

    # Lambda
    _safe_delete("Lambda function", lambda: clients["lambda_"].delete_function(
        FunctionName=RESOURCE_NAMES["lambda_function"]
    ))

    # EventBridge rule (must remove targets first)
    try:
        clients["events"].remove_targets(
            Rule=RESOURCE_NAMES["eventbridge_rule"],
            Ids=["KillSwitchLambda"],
        )
    except ClientError:
        pass
    _safe_delete("EventBridge rule", lambda: clients["events"].delete_rule(
        Name=RESOURCE_NAMES["eventbridge_rule"]
    ))

    # CloudTrail
    _safe_delete("CloudTrail trail", lambda: clients["cloudtrail"].delete_trail(
        Name=RESOURCE_NAMES["trail_name"]
    ))

    # DynamoDB
    _safe_delete("DynamoDB table", lambda: clients["dynamodb"].delete_table(
        TableName=RESOURCE_NAMES["baseline_table"]
    ))

    # IAM role (delete inline policy first)
    _safe_delete("Lambda role policy", lambda: clients["iam"].delete_role_policy(
        RoleName=RESOURCE_NAMES["lambda_role"],
        PolicyName=RESOURCE_NAMES["lambda_policy"],
    ))
    _safe_delete("Lambda role", lambda: clients["iam"].delete_role(
        RoleName=RESOURCE_NAMES["lambda_role"]
    ))

    # IAM attacker user (delete keys + inline policies + user)
    try:
        keys = clients["iam"].list_access_keys(
            UserName=RESOURCE_NAMES["attacker_user"]
        )["AccessKeyMetadata"]
        for key in keys:
            clients["iam"].delete_access_key(
                UserName=RESOURCE_NAMES["attacker_user"],
                AccessKeyId=key["AccessKeyId"],
            )
        policies = clients["iam"].list_user_policies(
            UserName=RESOURCE_NAMES["attacker_user"]
        )["PolicyNames"]
        for policy in policies:
            clients["iam"].delete_user_policy(
                UserName=RESOURCE_NAMES["attacker_user"],
                PolicyName=policy,
            )
    except ClientError:
        pass
    _safe_delete("IAM attacker user", lambda: clients["iam"].delete_user(
        UserName=RESOURCE_NAMES["attacker_user"]
    ))

    # SNS
    _safe_delete("SNS topic", lambda: clients["sns"].delete_topic(TopicArn=sns_arn))

    # CloudWatch
    _safe_delete("CloudWatch log group", lambda: clients["logs"].delete_log_group(
        logGroupName=RESOURCE_NAMES["log_group"]
    ))

    # S3 — empty first, then delete
    for bucket in [test_bucket, log_bucket]:
        logger.info("Emptying bucket: %s", bucket)
        delete_all_objects(clients["s3"], bucket)
        _safe_delete(f"S3 bucket {bucket}", lambda b=bucket: clients["s3"].delete_bucket(Bucket=b))

    print("\n✓ Teardown complete. All Kill-Switch resources removed from AWS.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="teardown.py",
        description="Remove all Kill-Switch AWS resources created by setup.py.",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually delete resources. Without this flag, runs in dry-run mode.",
    )
    args = parser.parse_args()
    teardown(confirm=args.confirm)


if __name__ == "__main__":
    main()
