"""
run_local_demo.py

End-to-End Local Simulation Runner for the Cloud Ransomware Kill-Switch.
Runs Phases 1 through 4 offline using simulated AWS APIs and in-memory Neo4j graph.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Reconfigure stdout and stderr to use UTF-8 encoding on Windows to prevent UnicodeEncodeError
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

# Clear existing cache files to ensure a clean run
WORKSPACE_ROOT = Path(__file__).parent
LOCAL_CACHE_DIR = WORKSPACE_ROOT / "local_cache"
REPORTS_DIR = WORKSPACE_ROOT / "reports"

# Prepare environment variables for child processes
demo_env = os.environ.copy()
demo_env["MOCK_MODE"] = "true"
demo_env["AWS_REGION"] = "us-east-1"
demo_env["BASELINE_TABLE"] = "killswitch-baselines"
# Set Python IO encoding to UTF-8 for subprocesses
demo_env["PYTHONIOENCODING"] = "utf-8"
# Add workspace root to PYTHONPATH so sub-processes can import common.mock_provider
demo_env["PYTHONPATH"] = str(WORKSPACE_ROOT) + os.pathsep + demo_env.get("PYTHONPATH", "")

def clean_local_cache():
    if LOCAL_CACHE_DIR.exists():
        shutil.rmtree(LOCAL_CACHE_DIR)
    LOCAL_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    if REPORTS_DIR.exists():
        shutil.rmtree(REPORTS_DIR)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def run_step(command: list[str], description: str) -> str:
    print(f"\n{'='*80}")
    print(f"RUNNING: {description}")
    print(f"Command: {' '.join(command)}")
    print(f"{'='*80}\n")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=True, env=demo_env)
        print(result.stdout)
        if result.stderr:
            print(f"Stderr logs:\n{result.stderr}", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Step failed with code {e.returncode}")
        print(f"Stdout:\n{e.output}")
        print(f"Stderr:\n{e.stderr}", file=sys.stderr)
        sys.exit(1)

def main():
    print("\n" + "#"*80)
    print("###  CLOUD SECURITY RANSOMWARE KILL-SWITCH - LOCAL SIMULATION DEMO  ###")
    print("#"*80 + "\n")
    
    # 1. Clean cache
    clean_local_cache()
    
    # 2. Run Setup (Phase 1)
    run_step([sys.executable, "infra/setup.py"], "Phase 1: Provisioning Local Mock Infrastructure")
    
    # 3. Run Pipeline Acceptance Test (Phase 1)
    run_step([sys.executable, "infra/verify_pipeline.py"], "Phase 1 Acceptance Test: Verifying CloudTrail Pipeline")
    
    # 4. Ingest IAM and build Graph (Phase 3)
    run_step([sys.executable, "iam_graph/ingest.py"], "Phase 3: Ingesting IAM Policy Snapshot")
    run_step([sys.executable, "iam_graph/graph_builder.py", "--clear"], "Phase 3: Building Mock Neo4j Graph")
    
    # 5. Run Pattern Detection (Phase 3)
    run_step([sys.executable, "iam_graph/patterns.py", "--run-all", "--output", "reports/patterns.json"], "Phase 3: Running Cypher Privilege Escalation Scan (RSL-01-06)")
    
    # 6. Run Risk Scorer (Phase 3)
    run_step([sys.executable, "iam_graph/risk_score.py"], "Phase 3: Scoring Principal Risk & Writing to mock DynamoDB")
    
    # 7. Establish Baseline Traffic (Phase 2)
    # We run for a short duration with custom settings for the simulator to seed baseline
    # Set MIN_OBSERVATIONS low in environment to allow quick baseline seeding
    demo_env["MIN_OBSERVATIONS"] = "1"
    demo_env["WINDOW_SECONDS"] = "1"
    
    run_step([sys.executable, "simulator/attacker.py", "--mode", "seed-baseline", "--rate", "10", "--duration", "5"], "Phase 2: Seeding Normal Traffic Baseline")
    
    # 8. Execute Attack & Verify Kill-Switch Trigger (Phase 2)
    run_step([sys.executable, "simulator/attacker.py", "--mode", "attack", "--count", "25", "--rate", "10"], "Phase 2: Simulating Ransomware Attack (Burst PutObject)")
    
    # 9. Verify Phase 4 Exploitation Block
    # Attempt escalation on the attacker principal. Since keys were deleted in Step 8, this should report BLOCKED!
    run_step([sys.executable, "iam_graph/escalation_test.py"], "Phase 4: Running Sandbox Exploitability Verification (RSL-01)")
    
    # 10. Generate Least-Privilege Policy (Phase 4)
    run_step([sys.executable, "iam_graph/remediate.py", "--principal", "arn:aws:iam::123456789012:user/killswitch-attacker"], "Phase 4: Auto-Generating Tightened Least-Privilege Policy")
    
    print("\n" + "#"*80)
    print("###             LOCAL SIMULATION DEMO COMPLETED SUCCESSFULLY             ###")
    print("###  Phases 1-4 completed end-to-end in offline simulated sandbox environment. ###")
    print("#"*80 + "\n")

if __name__ == "__main__":
    main()
