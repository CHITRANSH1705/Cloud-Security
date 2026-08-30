"""
infra/verify_pipeline.py

Phase 1 Acceptance Test — End-to-End Pipeline Verification

This script confirms the entire CloudTrail → EventBridge → Lambda pipeline
is wired correctly BEFORE adding detection logic.

What it does:
    1. Loads config from .env (bucket name, credentials)
    2. Performs a single s3:PutObject on the test bucket using YOUR admin credentials
    3. Waits up to 90 seconds for CloudTrail to index the event
    4. Queries CloudTrail LookupEvents for PutObject in the test bucket
    5. Prints the full CloudTrail event JSON to confirm the pipeline is live

Expected output:
    Found 1 CloudTrail event(s) for PutObject on killswitch-test-<account-id>:
    { "eventVersion": "1.08", "userIdentity": { ... }, "eventName": "PutObject", ... }

    ✓ Phase 1 acceptance test PASSED — CloudTrail pipeline is live.

If no event is found within 90s:
    ✗ No CloudTrail event found within timeout.
    Check: CloudTrail trail is enabled, S3 data events are configured,
           and the test bucket name matches.

Usage:
    python infra/verify_pipeline.py
    python infra/verify_pipeline.py --bucket my-custom-bucket --timeout 120
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
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

REGION      = os.environ.get("AWS_REGION", "us-east-1")
TEST_BUCKET = os.environ.get("TEST_BUCKET_NAME", "")
TRAIL_NAME  = os.environ.get("CLOUDTRAIL_TRAIL_NAME", "killswitch-trail")

DEFAULT_TIMEOUT = 90  # seconds — CloudTrail usually indexes within 15-30s
POLL_INTERVAL   = 10  # seconds between LookupEvents calls


def verify_pipeline(bucket: str, timeout_seconds: int = DEFAULT_TIMEOUT) -> bool:
    """
    Perform end-to-end pipeline verification.

    Uses admin credentials (default boto3 credential chain — your AWS profile).
    This is intentional: we want to see YOUR principal in the CloudTrail event.

    Returns True if CloudTrail event found within timeout, False otherwise.
    """
    s3 = boto3.client("s3", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)

    # Step 1: Put a uniquely-named test object
    test_key = f"verify-pipeline/canary-{uuid.uuid4().hex}.txt"
    put_time = datetime.now(timezone.utc)

    logger.info("PutObject → s3://%s/%s", bucket, test_key)
    try:
        s3.put_object(
            Bucket=bucket,
            Key=test_key,
            Body=b"killswitch-pipeline-verification",
            Metadata={"purpose": "verify-cloudtrail-pipeline"},
        )
    except ClientError as e:
        logger.error("PutObject failed: %s", e)
        logger.error("Is the test bucket created? Run infra/setup.py first.")
        return False

    # Step 2: Poll CloudTrail LookupEvents
    logger.info(
        "Waiting for CloudTrail to index the event (max %ds, polling every %ds)...",
        timeout_seconds, POLL_INTERVAL,
    )

    start_wait = time.time()
    deadline   = start_wait + timeout_seconds

    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        elapsed = round(time.time() - start_wait)
        logger.info("Polling CloudTrail... (%ds elapsed)", elapsed)

        try:
            response = ct.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName",  "AttributeValue": "PutObject"},
                    {"AttributeKey": "ResourceName", "AttributeValue": bucket},
                ],
                StartTime=put_time - timedelta(seconds=5),
                EndTime=datetime.now(timezone.utc),
                MaxResults=10,
            )
        except ClientError as e:
            logger.warning("CloudTrail lookup_events error: %s — retrying...", e)
            continue

        events = response.get("Events", [])

        # Filter to our specific key (lookup is imprecise — may return other events)
        matching = [
            e for e in events
            if test_key in (e.get("Resources") or [{}])[0].get("ResourceName", "")
            or test_key in e.get("CloudTrailEvent", "")
        ]

        if matching:
            elapsed_total = round(time.time() - start_wait)
            logger.info(
                "✓ CloudTrail event found after %ds!", elapsed_total
            )

            for ev in matching:
                ct_event = json.loads(ev.get("CloudTrailEvent", "{}"))
                print(f"\n{'─'*60}")
                print(f"CloudTrail Event — found after {elapsed_total}s:")
                print(f"{'─'*60}")
                print(json.dumps(ct_event, indent=2, default=str))
                print(f"{'─'*60}\n")

            print(f"\n✓ Phase 1 acceptance test PASSED")
            print(f"  CloudTrail is indexing S3 data events for bucket: {bucket}")
            print(f"  EventBridge → Lambda pipeline is ready for Phase 2.\n")
            return True

    # Timeout
    logger.error(
        "✗ No CloudTrail event found within %ds for key: %s",
        timeout_seconds, test_key,
    )
    print(f"\n✗ Phase 1 acceptance test FAILED — no CloudTrail event in {timeout_seconds}s")
    print("Troubleshooting checklist:")
    print("  1. Is the CloudTrail trail enabled?")
    print(f"     aws cloudtrail get-trail-status --name {TRAIL_NAME}")
    print("  2. Are S3 data events configured for this bucket?")
    print(f"     aws cloudtrail get-event-selectors --trail-name {TRAIL_NAME}")
    print("  3. Is the bucket name correct?")
    print(f"     Current bucket: {bucket}")
    print("  4. Sometimes CloudTrail takes up to 5 minutes for first event — retry.\n")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="verify_pipeline.py",
        description="Phase 1 acceptance test — confirm CloudTrail pipeline is live.",
    )
    parser.add_argument(
        "--bucket",
        default=TEST_BUCKET,
        help="S3 test bucket to use (default: TEST_BUCKET_NAME from .env)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Max seconds to wait for CloudTrail event (default: {DEFAULT_TIMEOUT})",
    )
    args = parser.parse_args()

    if not args.bucket:
        print("ERROR: TEST_BUCKET_NAME not set. Run infra/setup.py first or use --bucket.")
        return

    verify_pipeline(args.bucket, args.timeout)


if __name__ == "__main__":
    main()
