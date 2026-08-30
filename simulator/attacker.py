"""
simulator/attacker.py

Controlled S3 Attack Simulator — Demo Tool for Kill-Switch Testing

This script simulates a compromised principal hammering an S3 bucket.
It uses ONLY the attacker IAM user's credentials, never your admin credentials.
Revoking the attacker's keys does not affect your admin session.

Modes:
    --mode normal
        Sends 1 object PUT every ~30 seconds for a specified duration.
        This is used to establish a baseline and confirm zero false positives
        during normal-rate traffic.

    --mode attack
        Sends N objects as fast as possible within a short burst window.
        This triggers the kill-switch detector. After detection fires, the next
        request returns AccessDenied — the observable acceptance-test outcome.

    --mode seed-baseline
        Sends sustained traffic at a configurable rate for several windows
        to establish a stable EWMA baseline for this principal before attack
        mode. Use this to test the "high-baseline principal" acceptance test.

Usage:
    # Step 1: establish baseline (run for a few minutes)
    python simulator/attacker.py --mode normal --duration 300

    # Step 2: trigger attack
    python simulator/attacker.py --mode attack --count 200 --rate 50

    # Step 3: confirm AccessDenied (attacker.py will show the error)

    # High-baseline principal test:
    python simulator/attacker.py --mode seed-baseline --rate 200 --duration 600
    python simulator/attacker.py --mode attack --rate 200
    # Expected: NO alert (200/min is normal for this principal)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

# Import mock provider first to monkey-patch if MOCK_MODE is true
try:
    import common.mock_provider
except ImportError:
    pass

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Rich for nicer CLI output
try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Configuration (read from .env — never hardcoded)
# ─────────────────────────────────────────────────────────────────────────────

ATTACKER_KEY_ID      = os.environ.get("ATTACKER_ACCESS_KEY_ID")
ATTACKER_SECRET_KEY  = os.environ.get("ATTACKER_SECRET_ACCESS_KEY")
TEST_BUCKET          = os.environ.get("TEST_BUCKET_NAME")
REGION               = os.environ.get("AWS_REGION", "us-east-1")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

console = Console() if RICH_AVAILABLE else None


def log(msg: str, style: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    if RICH_AVAILABLE and console:
        console.print(f"[dim]{ts}[/dim] {msg}", style=style or None)
    else:
        print(f"{ts} {msg}")


def get_s3_client() -> boto3.client:
    """
    Return an S3 client using ONLY the attacker's credentials.
    These credentials are explicitly passed — boto3 will NOT fall back
    to your admin profile / instance role / environment credentials.
    """
    if not ATTACKER_KEY_ID or not ATTACKER_SECRET_KEY:
        print(
            "ERROR: ATTACKER_ACCESS_KEY_ID and ATTACKER_SECRET_ACCESS_KEY must be set in .env\n"
            "Run infra/setup.py first to create the attacker IAM user and keys.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not TEST_BUCKET:
        print("ERROR: TEST_BUCKET_NAME must be set in .env", file=sys.stderr)
        sys.exit(1)

    return boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id=ATTACKER_KEY_ID,
        aws_secret_access_key=ATTACKER_SECRET_KEY,
    )


def put_object(s3: boto3.client, bucket: str, key: str, body: bytes = b"test") -> dict:
    """Attempt a PutObject. Returns result dict with status."""
    start = time.time()
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=body)
        elapsed = time.time() - start
        return {"status": "OK", "key": key, "latency_ms": round(elapsed * 1000)}
    except ClientError as e:
        elapsed = time.time() - start
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        return {
            "status":     "ERROR",
            "error_code": code,
            "error_msg":  msg,
            "key":        key,
            "latency_ms": round(elapsed * 1000),
        }


def delete_object(s3: boto3.client, bucket: str, key: str) -> dict:
    """Attempt a DeleteObject. Returns result dict with status."""
    start = time.time()
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        elapsed = time.time() - start
        return {"status": "OK", "key": key, "latency_ms": round(elapsed * 1000)}
    except ClientError as e:
        elapsed = time.time() - start
        code = e.response["Error"]["Code"]
        return {
            "status":     "ERROR",
            "error_code": code,
            "key":        key,
            "latency_ms": round(elapsed * 1000),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Simulation modes
# ─────────────────────────────────────────────────────────────────────────────

def mode_normal(s3: boto3.client, bucket: str, duration_seconds: int, interval: float = 30.0) -> None:
    """
    Normal traffic mode: 1 PUT every ~interval seconds for duration_seconds.
    Expected outcome: ZERO alerts from the kill-switch.
    """
    log(f"[bold green]MODE: NORMAL[/bold green] — duration={duration_seconds}s interval={interval}s bucket={bucket}")
    log("This mode establishes an EWMA baseline. Expect zero kill-switch alerts.")
    log("─" * 60)

    end_time  = time.time() + duration_seconds
    sent      = 0
    errors    = 0
    start_run = time.time()

    while time.time() < end_time:
        key    = f"normal/test-object-{uuid.uuid4().hex[:8]}.dat"
        result = put_object(s3, bucket, key)
        sent  += 1

        if result["status"] == "OK":
            log(f"PUT #{sent:>4} [green]OK[/green]    key={key} latency={result['latency_ms']}ms")
        else:
            errors += 1
            log(
                f"PUT #{sent:>4} [red]{result['error_code']}[/red] {result.get('error_msg','')}",
                style="red" if not RICH_AVAILABLE else "",
            )
            if result.get("error_code") == "AccessDenied":
                log("[bold red]⚠ AccessDenied — kill-switch may have triggered unexpectedly![/bold red]")

        remaining = end_time - time.time()
        if remaining > 0:
            time.sleep(min(interval, remaining))

    elapsed = time.time() - start_run
    log("─" * 60)
    log(f"Normal mode complete: sent={sent} errors={errors} elapsed={elapsed:.1f}s")
    if errors == 0:
        log("[bold green]✓ No errors — no false positives during normal traffic.[/bold green]")


def mode_attack(
    s3: boto3.client,
    bucket: str,
    count: int = 200,
    rate_per_second: float = 20.0,
) -> None:
    """
    Attack mode: burst N PUTs as fast as possible.
    Expected outcome: kill-switch fires, subsequent calls return AccessDenied.

    Reports:
        - Detection time (from first PUT to first AccessDenied response)
        - Total objects uploaded before the block
        - Exact timestamp of AccessDenied
    """
    log(f"[bold red]MODE: ATTACK[/bold red] — target={count} objects rate={rate_per_second}/s bucket={bucket}")
    log("This mode triggers the kill-switch. Watch for AccessDenied responses.")
    log("─" * 60)

    min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
    sent         = 0
    blocked_at   = None
    objects_before_block = 0
    start_time   = time.time()
    first_put_ts = None

    for i in range(count):
        key    = f"attack/burst-{uuid.uuid4().hex[:8]}.dat"
        result = put_object(s3, bucket, key, body=b"x" * 1024)
        sent  += 1

        if first_put_ts is None:
            first_put_ts = time.time()

        if result["status"] == "OK":
            objects_before_block += 1
            log(f"PUT #{sent:>4} [green]OK[/green]    key={key} latency={result['latency_ms']}ms")
        else:
            if result.get("error_code") == "AccessDenied":
                if blocked_at is None:
                    blocked_at = time.time()
                    detection_time_s = blocked_at - start_time
                    log(
                        f"\n[bold red]🚨 BLOCKED at PUT #{sent}[/bold red] — "
                        f"AccessDenied received. Kill-switch fired!\n"
                        f"  Detection time:         [yellow]{detection_time_s:.2f}s[/yellow]\n"
                        f"  Objects before block:   [yellow]{objects_before_block}[/yellow]\n"
                        f"  Block timestamp:        {datetime.now(timezone.utc).isoformat()}"
                    )
                else:
                    log(f"PUT #{sent:>4} [red]AccessDenied[/red] (still blocked) latency={result['latency_ms']}ms")
            else:
                log(f"PUT #{sent:>4} [red]{result['error_code']}[/red] {result.get('error_msg','')}")

        if min_interval > 0:
            time.sleep(min_interval)

    elapsed = time.time() - start_time
    log("─" * 60)
    log(f"Attack complete: attempted={count} blocked_at={objects_before_block} elapsed={elapsed:.1f}s")

    if blocked_at:
        log(
            f"\n[bold]Attack Summary:[/bold]\n"
            f"  Kill-switch triggered:  [green]YES[/green]\n"
            f"  Detection time:         {blocked_at - start_time:.2f}s\n"
            f"  Objects ingested:       {objects_before_block}\n"
            f"  Remaining blocked:      {count - objects_before_block}"
        )
    else:
        log(
            "[bold red]WARNING: No AccessDenied received in attack mode.[/bold red]\n"
            "Possible causes:\n"
            "  • Lambda has not finished processing events yet (CloudTrail has ~15s delay)\n"
            "  • MIN_OBSERVATIONS not yet met (need 5 prior windows)\n"
            "  • EventBridge rule not correctly targeting Lambda\n"
            "  Check CloudWatch Logs /killswitch/remediations for Lambda output."
        )


def mode_seed_baseline(
    s3: boto3.client,
    bucket: str,
    rate_per_minute: int = 10,
    duration_seconds: int = 600,
) -> None:
    """
    Seed a stable high-rate baseline for a principal.
    Used for the acceptance test: 'high-baseline principal should not false-positive
    at the same absolute rate that flagged a low-baseline principal.'
    """
    log(
        f"[bold yellow]MODE: SEED-BASELINE[/bold yellow] — "
        f"rate={rate_per_minute}/min duration={duration_seconds}s bucket={bucket}"
    )
    log("Seeding EWMA baseline. This establishes this principal's 'normal' rate.")
    log(f"Estimated windows to fill: {duration_seconds // 60} × 60s windows")
    log("─" * 60)

    interval = 60.0 / rate_per_minute
    end_time = time.time() + duration_seconds
    sent     = 0
    windows  = 0
    window_start = time.time()

    while time.time() < end_time:
        key    = f"baseline/seed-{uuid.uuid4().hex[:8]}.dat"
        result = put_object(s3, bucket, key)
        sent  += 1

        if result["status"] == "OK":
            log(f"PUT #{sent:>5} [green]OK[/green] key={key}")
        else:
            log(f"PUT #{sent:>5} [red]{result['error_code']}[/red]")

        # Track windows
        if time.time() - window_start >= 60:
            windows += 1
            log(f"[dim]Window {windows} complete — {sent} events so far[/dim]")
            window_start = time.time()

        remaining = end_time - time.time()
        if remaining > 0:
            time.sleep(min(interval, remaining))

    log("─" * 60)
    log(f"Baseline seeding complete: sent={sent} windows≈{windows} rate≈{sent*60//duration_seconds}/min")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="attacker.py",
        description="Kill-Switch Demo — Controlled S3 attack simulator",
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "attack", "seed-baseline"],
        required=True,
        help="Simulation mode",
    )
    parser.add_argument(
        "--bucket",
        default=TEST_BUCKET,
        help="S3 bucket to target (default: TEST_BUCKET_NAME from .env)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Duration in seconds for 'normal' and 'seed-baseline' modes (default: 300)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=200,
        help="Number of objects to PUT in 'attack' mode (default: 200)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=20.0,
        help=(
            "For 'attack': requests per second (default: 20.0). "
            "For 'seed-baseline': requests per minute (default used as per-min)."
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Seconds between PUTs in 'normal' mode (default: 30.0)",
    )

    args = parser.parse_args()
    bucket = args.bucket

    if not bucket:
        print("ERROR: No bucket specified. Set TEST_BUCKET_NAME in .env or use --bucket.", file=sys.stderr)
        sys.exit(1)

    s3 = get_s3_client()

    log(f"Attacker principal: key_id={ATTACKER_KEY_ID[:8] if ATTACKER_KEY_ID else 'NOT SET'}***")
    log(f"Target bucket: {bucket}")
    log("")

    if args.mode == "normal":
        mode_normal(s3, bucket, args.duration, args.interval)
    elif args.mode == "attack":
        mode_attack(s3, bucket, args.count, args.rate)
    elif args.mode == "seed-baseline":
        mode_seed_baseline(s3, bucket, int(args.rate), args.duration)


if __name__ == "__main__":
    main()
