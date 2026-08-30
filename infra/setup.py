"""
infra/setup.py

AWS Sandbox Provisioner — Cloud Ransomware Kill-Switch

Provisions ALL required AWS resources from scratch.
Safe to re-run — uses idempotent create-or-skip logic throughout.

Resources created:
    1. S3 test bucket          (target of attacker simulation)
    2. S3 CloudTrail log bucket (CloudTrail writes logs here)
    3. DynamoDB: killswitch-baselines (EWMA state per principal)
    4. CloudTrail trail         (S3 data events on the test bucket)
    5. Lambda execution IAM role + inline policy
    6. Lambda function          (rate_monitor.py + revoke.py + attack_mapping.py)
    7. EventBridge rule         (routes CloudTrail events to Lambda)
    8. EventBridge → Lambda permission
    9. SNS topic                (ALERT-tier notifications)
   10. IAM attacker user        (killswitch-attacker, scoped to test bucket only)
   11. Attacker access key      (printed to screen, written to .env)

Estimated AWS costs for a demo run (~1 hour):
    CloudTrail data events: $0.10 per 100,000 events (~1000 events = $0.001)
    Lambda invocations:     First 1M free
    DynamoDB:               Free tier (25 GB storage, 25 RCU/WCU)
    S3:                     First 5 GB free
    EventBridge:            $1.00 per million custom events
    SNS:                    First 1M free
    TOTAL for demo: < $0.01

Usage:
    python infra/setup.py             # Full provision
    python infra/setup.py --dry-run   # Print what would be created (no AWS calls)
    python infra/setup.py --teardown  # Destroy all resources (use teardown.py instead)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv, set_key

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

REGION = os.environ.get("AWS_REGION", "us-east-1")
ENV_FILE = Path(__file__).parent.parent / ".env"

RESOURCE_NAMES = {
    "lambda_function":    "killswitch-detector",
    "lambda_role":        "killswitch-lambda-role",
    "lambda_handler":     "lambda_handler.handler",
    "eventbridge_rule":   "killswitch-s3-events",
    "baseline_table":     "killswitch-baselines",
    "trail_name":         "killswitch-trail",
    "attacker_user":      "killswitch-attacker",
    "sns_topic":          "killswitch-alerts",
    "log_group":          "/killswitch/remediations",
}

# Repo root (parent of infra/)
REPO_ROOT = Path(__file__).parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# AWS clients
# ─────────────────────────────────────────────────────────────────────────────

def get_clients(region: str) -> dict[str, Any]:
    return {
        "sts":         boto3.client("sts",         region_name=region),
        "s3":          boto3.client("s3",          region_name=region),
        "iam":         boto3.client("iam",         region_name=region),
        "dynamodb":    boto3.client("dynamodb",    region_name=region),
        "cloudtrail":  boto3.client("cloudtrail",  region_name=region),
        "lambda_":     boto3.client("lambda",      region_name=region),
        "events":      boto3.client("events",      region_name=region),
        "sns":         boto3.client("sns",         region_name=region),
        "logs":        boto3.client("logs",        region_name=region),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: S3 buckets
# ─────────────────────────────────────────────────────────────────────────────

def create_test_bucket(s3: Any, account_id: str, region: str) -> str:
    bucket_name = f"killswitch-test-{account_id}"
    _create_bucket(s3, bucket_name, region)
    # Enable versioning (so we can test Delete + DeleteMarker events)
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    logger.info("Test bucket ready: %s", bucket_name)
    return bucket_name


def create_cloudtrail_log_bucket(s3: Any, account_id: str, region: str) -> str:
    """
    Create an S3 bucket for CloudTrail to write logs to, with the required
    bucket policy that allows the CloudTrail service to write objects.
    """
    bucket_name = f"killswitch-cloudtrail-{account_id}"
    _create_bucket(s3, bucket_name, region)

    # CloudTrail requires a specific bucket policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }

    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        logger.info("CloudTrail log bucket ready with policy: %s", bucket_name)
    except ClientError as e:
        logger.warning("Could not set bucket policy on %s: %s", bucket_name, e)

    return bucket_name


def _create_bucket(s3: Any, bucket_name: str, region: str) -> None:
    """Create bucket idempotently (skip if already exists and we own it)."""
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        logger.info("Created bucket: %s", bucket_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            logger.info("Bucket already exists (owned by you): %s", bucket_name)
        else:
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: DynamoDB table
# ─────────────────────────────────────────────────────────────────────────────

def create_dynamodb_table(ddb: Any) -> None:
    table_name = RESOURCE_NAMES["baseline_table"]
    try:
        ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "principal_arn", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "principal_arn", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",  # no capacity planning needed for demo
        )
        # Wait for table to become active
        waiter = ddb.get_waiter("table_exists")
        waiter.wait(TableName=table_name)
        logger.info("DynamoDB table created: %s", table_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceInUseException":
            logger.info("DynamoDB table already exists: %s", table_name)
        else:
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Lambda IAM role
# ─────────────────────────────────────────────────────────────────────────────

def create_lambda_role(iam: Any, account_id: str, region: str) -> str:
    """Create the Lambda execution role with least-privilege inline policy."""
    role_name = RESOURCE_NAMES["lambda_role"]

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }

    # Create role (idempotent)
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Kill-Switch Lambda execution role — auto-created by setup.py",
        )
        role_arn = response["Role"]["Arn"]
        logger.info("Created Lambda role: %s", role_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
            logger.info("Lambda role already exists: %s", role_arn)
        else:
            raise

    # Inline execution policy (least-privilege)
    exec_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":      "CloudWatchLogs",
                "Effect":   "Allow",
                "Action":   ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid":      "DynamoDBBaselines",
                "Effect":   "Allow",
                "Action":   ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
                "Resource": f"arn:aws:dynamodb:{region}:{account_id}:table/{RESOURCE_NAMES['baseline_table']}",
            },
            {
                "Sid":    "IAMRemediation",
                "Effect": "Allow",
                "Action": [
                    "iam:ListAccessKeys",
                    "iam:DeleteAccessKey",
                    "iam:PutUserPolicy",
                    "iam:AttachUserPolicy",
                ],
                "Resource": f"arn:aws:iam::{account_id}:user/{RESOURCE_NAMES['attacker_user']}",
            },
            {
                "Sid":      "SNSAlerts",
                "Effect":   "Allow",
                "Action":   "sns:Publish",
                "Resource": f"arn:aws:sns:{region}:{account_id}:{RESOURCE_NAMES['sns_topic']}",
            },
        ],
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="killswitch-lambda-exec-policy",
        PolicyDocument=json.dumps(exec_policy),
    )
    logger.info("Lambda role policy attached.")

    # Give IAM a moment to propagate (Lambda create will fail immediately otherwise)
    time.sleep(10)
    return role_arn


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Package Lambda ZIP
# ─────────────────────────────────────────────────────────────────────────────

def build_lambda_zip(tmp_dir: Path) -> Path:
    """
    Package the Lambda function as a ZIP.

    The ZIP structure (flat, not nested):
        lambda_handler.py    ← detector/rate_monitor.py (handler entry point)
        attack_mapping.py    ← common/attack_mapping.py
        revoke.py            ← remediator/revoke.py

    The handler function is: lambda_handler.handler
    (matching RESOURCE_NAMES["lambda_handler"])
    """
    src_root = REPO_ROOT
    zip_path = tmp_dir / "killswitch_lambda.zip"

    files_to_package = [
        (src_root / "detector"    / "rate_monitor.py",   "lambda_handler.py"),
        (src_root / "common"      / "attack_mapping.py", "attack_mapping.py"),
        (src_root / "remediator"  / "revoke.py",         "revoke.py"),
    ]

    # Verify all source files exist before zipping
    missing = [str(src) for src, _ in files_to_package if not src.exists()]
    if missing:
        logger.error("Cannot package Lambda — source files missing: %s", missing)
        sys.exit(1)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for src_path, zip_name in files_to_package:
            zf.write(src_path, zip_name)
            logger.info("  Added to ZIP: %s → %s", src_path.name, zip_name)

    logger.info("Lambda ZIP created: %s (%d bytes)", zip_path, zip_path.stat().st_size)
    return zip_path


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Lambda function
# ─────────────────────────────────────────────────────────────────────────────

def deploy_lambda(
    lambda_: Any,
    role_arn: str,
    zip_path: Path,
    test_bucket: str,
    sns_topic_arn: str,
    account_id: str,
    region: str,
) -> str:
    """Create or update the Lambda function. Returns the function ARN."""
    function_name = RESOURCE_NAMES["lambda_function"]

    env_vars = {
        "BASELINE_TABLE":              RESOURCE_NAMES["baseline_table"],
        "AWS_REGION":                  region,
        "EWMA_ALPHA":                  "0.3",
        "Z_SCORE_THRESHOLD":           "4.0",
        "RATE_MULTIPLIER_THRESHOLD":   "10.0",
        "WINDOW_SECONDS":              "60",
        "MIN_OBSERVATIONS":            "5",
        "SNS_ALERT_TOPIC_ARN":         sns_topic_arn,
    }

    zip_bytes = zip_path.read_bytes()

    try:
        response = lambda_.create_function(
            FunctionName=function_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler=RESOURCE_NAMES["lambda_handler"],
            Code={"ZipFile": zip_bytes},
            Description="Kill-Switch detector — EWMA-based S3 anomaly detector",
            Timeout=30,
            MemorySize=256,
            Environment={"Variables": env_vars},
        )
        function_arn = response["FunctionArn"]
        logger.info("Lambda function created: %s", function_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            # Update existing function
            logger.info("Lambda already exists — updating code...")
            lambda_.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_bytes,
            )
            lambda_.update_function_configuration(
                FunctionName=function_name,
                Environment={"Variables": env_vars},
            )
            function_arn = (
                lambda_.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]
            )
            logger.info("Lambda function updated: %s", function_arn)
        else:
            raise

    # Wait for function to be active
    waiter = lambda_.get_waiter("function_active")
    waiter.wait(FunctionName=function_name)
    return function_arn


# ─────────────────────────────────────────────────────────────────────────────
# Step 6: CloudTrail trail
# ─────────────────────────────────────────────────────────────────────────────

def create_cloudtrail(
    ct: Any, log_bucket: str, test_bucket: str, account_id: str
) -> str:
    """Create (or verify) a CloudTrail trail with S3 data events enabled."""
    trail_name = RESOURCE_NAMES["trail_name"]

    try:
        response = ct.create_trail(
            Name=trail_name,
            S3BucketName=log_bucket,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        trail_arn = response["TrailARN"]
        logger.info("CloudTrail trail created: %s", trail_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "TrailAlreadyExistsException":
            trail_arn = ct.get_trail(Name=trail_name)["Trail"]["TrailARN"]
            logger.info("CloudTrail trail already exists: %s", trail_arn)
        else:
            raise

    # Enable trail (start logging)
    ct.start_logging(Name=trail_name)
    logger.info("CloudTrail logging started.")

    # Configure S3 data events — Advanced Event Selectors (more granular than basic selectors)
    # We only log PutObject, DeleteObject, GetObject on the test bucket.
    # This minimizes CloudTrail costs to essentially $0 for a demo.
    ct.put_event_selectors(
        TrailName=trail_name,
        AdvancedEventSelectors=[
            {
                "Name": "KillSwitch S3 Data Events",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type",  "Equals": ["AWS::S3::Object"]},
                    {
                        "Field": "resources.ARN",
                        "StartsWith": [f"arn:aws:s3:::{test_bucket}/"],
                    },
                    {
                        "Field": "eventName",
                        "Equals": ["PutObject", "DeleteObject", "GetObject", "CopyObject"],
                    },
                ],
            }
        ],
    )
    logger.info("CloudTrail advanced event selectors configured for bucket: %s", test_bucket)
    return trail_arn


# ─────────────────────────────────────────────────────────────────────────────
# Step 7: EventBridge rule + Lambda target
# ─────────────────────────────────────────────────────────────────────────────

def create_eventbridge_rule(
    events: Any,
    lambda_: Any,
    function_arn: str,
    test_bucket: str,
    account_id: str,
    region: str,
) -> None:
    """Create EventBridge rule routing CloudTrail S3 events to Lambda."""
    rule_name = RESOURCE_NAMES["eventbridge_rule"]

    event_pattern = {
        "source":      ["aws.s3"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["s3.amazonaws.com"],
            "eventName":   ["PutObject", "DeleteObject", "CopyObject"],
            "requestParameters": {
                "bucketName": [test_bucket],
            },
        },
    }

    try:
        events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State="ENABLED",
            Description="Routes CloudTrail S3 data events to Kill-Switch Lambda detector",
        )
        logger.info("EventBridge rule created: %s", rule_name)
    except ClientError as e:
        logger.warning("EventBridge rule put_rule: %s", e)

    # Set Lambda as target
    events.put_targets(
        Rule=rule_name,
        Targets=[{
            "Id":  "KillSwitchLambda",
            "Arn": function_arn,
        }],
    )
    logger.info("EventBridge target set → %s", function_arn)

    # Grant EventBridge permission to invoke Lambda
    try:
        lambda_.add_permission(
            FunctionName=RESOURCE_NAMES["lambda_function"],
            StatementId="AllowEventBridgeInvoke",
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=f"arn:aws:events:{region}:{account_id}:rule/{rule_name}",
        )
        logger.info("Lambda resource policy updated — EventBridge can invoke.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            logger.info("Lambda permission for EventBridge already exists.")
        else:
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 8: SNS topic
# ─────────────────────────────────────────────────────────────────────────────

def create_sns_topic(sns: Any, region: str, account_id: str) -> str:
    """Create SNS topic for ALERT-tier notifications."""
    topic_name = RESOURCE_NAMES["sns_topic"]
    response = sns.create_topic(Name=topic_name)
    topic_arn = response["TopicArn"]
    logger.info("SNS topic ready: %s", topic_arn)
    return topic_arn


# ─────────────────────────────────────────────────────────────────────────────
# Step 9: Attacker IAM user
# ─────────────────────────────────────────────────────────────────────────────

def create_attacker_user(iam: Any, test_bucket: str, account_id: str) -> tuple[str, str]:
    """
    Create the attacker IAM user with minimal scoped permissions.

    Policy grants:
        s3:PutObject, s3:DeleteObject, s3:GetObject
        on ONLY the test bucket (not *, not account-wide)

    Returns (access_key_id, secret_access_key).
    """
    username = RESOURCE_NAMES["attacker_user"]

    # Create user
    try:
        iam.create_user(UserName=username)
        logger.info("IAM attacker user created: %s", username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            logger.info("IAM attacker user already exists: %s", username)
        else:
            raise

    # Scoped inline policy
    attacker_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid":      "KillSwitchTestBucketOnly",
            "Effect":   "Allow",
            "Action":   ["s3:PutObject", "s3:DeleteObject", "s3:GetObject"],
            "Resource": [
                f"arn:aws:s3:::{test_bucket}",
                f"arn:aws:s3:::{test_bucket}/*",
            ],
        }],
    }

    iam.put_user_policy(
        UserName=username,
        PolicyName="killswitch-attacker-s3-only",
        PolicyDocument=json.dumps(attacker_policy),
    )
    logger.info("Attacker user policy set (scoped to test bucket only).")

    # Check for existing keys
    existing_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    if existing_keys:
        logger.info("Attacker user already has %d access key(s). Using existing.", len(existing_keys))
        logger.warning(
            "Cannot retrieve secret for existing keys. "
            "If you need to rotate, run: aws iam delete-access-key --user-name %s --access-key-id <id>",
            username,
        )
        # Return placeholder — user must check .env or rotate manually
        return existing_keys[0]["AccessKeyId"], "EXISTING_KEY_SECRET_NOT_RETRIEVABLE"

    # Create new access key
    key_response = iam.create_access_key(UserName=username)
    access_key_id     = key_response["AccessKey"]["AccessKeyId"]
    secret_access_key = key_response["AccessKey"]["SecretAccessKey"]

    logger.info("Attacker access key created: %s", access_key_id)
    return access_key_id, secret_access_key


# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch log group
# ─────────────────────────────────────────────────────────────────────────────

def create_log_group(logs: Any) -> None:
    log_group = RESOURCE_NAMES["log_group"]
    try:
        logs.create_log_group(logGroupName=log_group)
        # Retain logs for 30 days to manage costs
        logs.put_retention_policy(logGroupName=log_group, retentionInDays=30)
        logger.info("CloudWatch log group created: %s", log_group)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
            logger.info("CloudWatch log group already exists: %s", log_group)
        else:
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Update .env file
# ─────────────────────────────────────────────────────────────────────────────

def update_env_file(
    test_bucket: str,
    log_bucket: str,
    sns_topic_arn: str,
    attacker_key_id: str,
    attacker_secret: str,
) -> None:
    """Write provisioned resource values back to .env for other scripts to use."""
    if not ENV_FILE.exists():
        # Copy from example if .env doesn't exist yet
        example = ENV_FILE.parent / ".env.example"
        if example.exists():
            shutil.copy(example, ENV_FILE)
            logger.info("Created .env from .env.example")

    def safe_set(key: str, value: str) -> None:
        try:
            set_key(str(ENV_FILE), key, value)
        except Exception as e:
            logger.warning("Could not write %s to .env: %s", key, e)

    safe_set("TEST_BUCKET_NAME",     test_bucket)
    safe_set("CLOUDTRAIL_LOG_BUCKET", log_bucket)
    safe_set("SNS_ALERT_TOPIC_ARN",  sns_topic_arn)
    safe_set("ATTACKER_ACCESS_KEY_ID", attacker_key_id)

    if attacker_secret != "EXISTING_KEY_SECRET_NOT_RETRIEVABLE":
        safe_set("ATTACKER_SECRET_ACCESS_KEY", attacker_secret)
    else:
        logger.warning(
            "Could not write ATTACKER_SECRET_ACCESS_KEY — key already existed. "
            "Check your existing .env or rotate the key manually."
        )

    logger.info(".env updated with provisioned resource values.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def provision(dry_run: bool = False) -> None:
    """
    Run the full provisioning sequence.
    Each step is idempotent — safe to re-run.
    """
    if dry_run:
        logger.info(
            "DRY RUN — no AWS API calls will be made. "
            "The following resources would be created:\n"
            "  S3 test bucket, S3 CloudTrail log bucket, DynamoDB table,\n"
            "  CloudTrail trail (S3 data events), Lambda IAM role,\n"
            "  Lambda function (killswitch-detector), EventBridge rule,\n"
            "  SNS topic, IAM attacker user + access key\n"
            "Remove --dry-run to proceed."
        )
        return

    clients = get_clients(REGION)

    # Get account ID
    account_id = clients["sts"].get_caller_identity()["Account"]
    logger.info("Provisioning in account %s / region %s", account_id, REGION)

    # Step 1: S3
    test_bucket = create_test_bucket(clients["s3"], account_id, REGION)
    log_bucket  = create_cloudtrail_log_bucket(clients["s3"], account_id, REGION)

    # Step 2: DynamoDB
    create_dynamodb_table(clients["dynamodb"])

    # Step 3: Lambda IAM role
    role_arn = create_lambda_role(clients["iam"], account_id, REGION)

    # Step 4 & 5: Package + deploy Lambda
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = build_lambda_zip(Path(tmp))

        # Step 8: SNS first (Lambda env var needs the ARN)
        sns_topic_arn = create_sns_topic(clients["sns"], REGION, account_id)

        function_arn = deploy_lambda(
            lambda_=clients["lambda_"],
            role_arn=role_arn,
            zip_path=zip_path,
            test_bucket=test_bucket,
            sns_topic_arn=sns_topic_arn,
            account_id=account_id,
            region=REGION,
        )

    # Step 6: CloudTrail
    create_cloudtrail(clients["cloudtrail"], log_bucket, test_bucket, account_id)

    # Step 7: EventBridge
    create_eventbridge_rule(
        events=clients["events"],
        lambda_=clients["lambda_"],
        function_arn=function_arn,
        test_bucket=test_bucket,
        account_id=account_id,
        region=REGION,
    )

    # Step 9: CloudWatch log group
    create_log_group(clients["logs"])

    # Step 10: Attacker user
    attacker_key_id, attacker_secret = create_attacker_user(
        clients["iam"], test_bucket, account_id
    )

    # Step 11: Update .env
    update_env_file(test_bucket, log_bucket, sns_topic_arn, attacker_key_id, attacker_secret)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print("  Kill-Switch Infrastructure Provisioned Successfully")
    print(f"{'═'*60}")
    print(f"  Account:           {account_id}")
    print(f"  Region:            {REGION}")
    print(f"  Test bucket:       {test_bucket}")
    print(f"  CloudTrail bucket: {log_bucket}")
    print(f"  Lambda function:   {RESOURCE_NAMES['lambda_function']}")
    print(f"  EventBridge rule:  {RESOURCE_NAMES['eventbridge_rule']}")
    print(f"  SNS topic:         {sns_topic_arn}")
    print(f"  Attacker user:     {RESOURCE_NAMES['attacker_user']}")
    print(f"  Attacker key ID:   {attacker_key_id}")
    if attacker_secret != "EXISTING_KEY_SECRET_NOT_RETRIEVABLE":
        print(f"  Attacker secret:   {attacker_secret[:8]}... (written to .env)")
    print(f"\n  Next step: python infra/verify_pipeline.py")
    print(f"{'═'*60}\n")

    print("⚠  SECURITY REMINDER:")
    print("   The attacker credentials above are for a THROWAWAY test principal.")
    print("   They are also saved in .env — do NOT commit .env to git.")
    print("   The .gitignore includes .env by default.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="setup.py",
        description="Provision AWS infrastructure for the Cloud Ransomware Kill-Switch.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created without making any AWS API calls.",
    )
    args = parser.parse_args()
    provision(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
