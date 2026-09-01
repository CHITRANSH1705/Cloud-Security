# Cloud Ransomware Kill-Switch & IAM Permission-Toxicity Detector

A portfolio-grade cloud security system demonstrating real detection, real remediation,
and real IAM graph analysis — running end-to-end against an AWS sandbox account.

---

## Phase Status (honest scope statement)

| Phase | Component | Status | Notes |
|---|---|---|---|
| 1 | Infrastructure provisioning |  Live | `infra/setup.py` + `infra/verify_pipeline.py` |
| 2 | Kill-Switch — EWMA rate detector |  Live | Lambda fires, EWMA baseline per principal |
| 2 | Kill-Switch — IAM remediation |  Live | Hard revoke / soft throttle / SNS alert actually execute |
| 2 | Kill-Switch — attack simulator |  Live | `simulator/attacker.py` with separate throwaway credentials |
| 3 | IAM permission graph (Neo4j) | ✅ Live | Full graph: principals, actions, resources, trust edges |
| 3 | Escalation chain detection (RSL-01–06) | ✅ Live | 6 Rhino Security Labs chains as Cypher queries |
| 3 | Risk scoring → kill-switch integration | ✅ Live | Scores written to Neo4j + DynamoDB; Lambda reads DDB |
| 4 | Sandbox exploitability test | ⛔ Not built | `escalation_test.py` has explicit `NotImplementedError` |
| 4 | Least-privilege policy generator | ⛔ Not built | `remediate.py` has explicit `NotImplementedError` |

**Every feature listed as Live runs end-to-end against a real AWS account — no stub detections.**
**Phases 1–3 were prioritized to completion; Phase 4 was explicitly cut, not silently stubbed.**

---

## Architecture

```
CloudTrail (S3 data events on test bucket)
         ↓
EventBridge rule (filters PutObject/DeleteObject for test bucket only)
         ↓
Lambda: detector/rate_monitor.py
  ├─ Per-principal EWMA baseline in DynamoDB
  ├─ Window evaluation: z-score > 4σ  OR  count > 10× baseline
  └─ Anomaly? → query DynamoDB for risk_score
                    ↓
         remediator/revoke.py (severity-scaled)
           ├─ risk_score ≥ 70 or None  → HARD: delete keys + deny policy
           ├─ risk_score 30–69         → SOFT: 30-min time-limited deny
           └─ risk_score < 30          → ALERT: SNS notification only
                    ↓
         CloudWatch Logs /killswitch/remediations
         (structured JSON: timestamp, principal, z_score, risk_score, action)

IAM policies (boto3 GetAccountAuthorizationDetails)
         ↓
iam_graph/graph_builder.py → Neo4j
  Nodes: Principal, Action, Resource, ManagedPolicy
  Edges: CAN_PERFORM, ON, CAN_ASSUME, MEMBER_OF
         ↓
iam_graph/patterns.py — Cypher queries for RSL-01 through RSL-06
         ↓
iam_graph/risk_score.py
  ├─ path_score  = 50 / shortest_path_to_admin  (shorter = worse)
  ├─ blast_score = min(50, distinct_reachable_resources × 5)
  └─ total_score = path_score + blast_score  (0–100)
         ↓
  Scores written → Neo4j p.risk_score + DynamoDB risk_score field
         ↓
  reports/iam_risk_report_<ts>.json
```

---

## Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Python | 3.11+ | [python.org](https://python.org) |
| Docker Desktop | Latest | [docker.com](https://docker.com) — for Neo4j |
| AWS CLI v2 | 2.x | [docs.aws.amazon.com](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| AWS account | Free tier | See next section |

### AWS Account Setup (if you don't have one)

1. Create a **free AWS account** at [aws.amazon.com](https://aws.amazon.com/free/)
   - Credit card required for identity verification, not charged for free-tier usage
   - Use a personal email + strong MFA from day 1

2. Create an admin IAM user for development (do NOT use root for daily use):
   ```
   AWS Console → IAM → Users → Create user
   Attach policy: AdministratorAccess
   Create access key (CLI)
   ```

3. Configure the AWS CLI:
   ```powershell
   aws configure
   # Enter: access key, secret key, us-east-1, json
   ```

4. Verify access:
   ```powershell
   aws sts get-caller-identity
   ```

**Estimated cost for a full demo run (~2 hours):** < $0.05
- CloudTrail data events: $0.10/100K events. A demo with ~1,000 events = $0.001
- Lambda: First 1M invocations free
- DynamoDB, S3, EventBridge, SNS: Free tier covers demo usage

---

## Setup

### 1. Clone and install dependencies

```powershell
cd "C:\Users\<you>\Desktop\Projects\cloud security"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```powershell
copy .env.example .env
# Open .env and set AWS_REGION (default: us-east-1)
# All other values are filled in by setup.py
```

### 3. Start Neo4j (for Phase 3)

```powershell
docker compose up -d
# Wait ~30s for Neo4j to start
# Browser: http://localhost:7474  (user: neo4j, password: killswitch-local-dev)
```

### 4. Provision AWS infrastructure

```powershell
python infra/setup.py
```

This creates all AWS resources and prints a summary including the attacker
access key. The key is also written to `.env` automatically.

**⚠ Never commit `.env` to git — it contains real credentials.**

### 5. Verify pipeline (Phase 1 acceptance test)

```powershell
python infra/verify_pipeline.py
```

Expected output: Full CloudTrail event JSON printed within ~30 seconds.
Only proceed to Phase 2 after this passes.

---

## Demo Script

### Phase 2 Demo — Kill-Switch

```powershell
# Terminal 1: Watch Lambda logs in real time
aws logs tail /killswitch/remediations --follow

# Terminal 2: Run the demo
# Step 1: Normal traffic — establish baseline, zero alerts
python simulator/attacker.py --mode normal --duration 300

# (Wait for 5+ windows = ~5 minutes)

# Step 2: Attack mode — triggers detection
python simulator/attacker.py --mode attack --count 200 --rate 20

# Watch Terminal 1 for the detection log entry with z_score, action taken, technique_id
# Watch Terminal 2 for AccessDenied responses after remediation
```

**Expected results to narrate:**
- Detection time: time from first PUT to first AccessDenied (printed by attacker.py)
- Objects ingested before block: printed by attacker.py
- Structured log in Terminal 1: `{ "z_score": X, "severity_tier": "HARD", "technique_id": "T1485", ... }`

```powershell
# Step 3: High-baseline acceptance test (no false positive)
python simulator/attacker.py --mode seed-baseline --rate 200 --duration 600
python simulator/attacker.py --mode attack --count 200 --rate 3  # same absolute rate as original attacker
# Expected: NO alert for high-baseline principal at same absolute rate
```

### Phase 3 Demo — Permission Graph

```powershell
# Ingest IAM policies
python iam_graph/ingest.py

# Build Neo4j graph
python iam_graph/graph_builder.py --clear

# Open http://localhost:7474 and run:
# MATCH (p:Principal)-[:CAN_PERFORM]->(a:Action) RETURN p,a LIMIT 50

# Run escalation chain detection
python iam_graph/patterns.py --run-all --output reports/patterns.json

# Score principals + write risk scores to DDB
python iam_graph/risk_score.py

# Read the report
cat reports/iam_risk_report_<latest-ts>.json
```

**Show in Neo4j Browser (copy-paste these Cypher queries):**

```cypher
-- Highlight all principals on escalation paths
MATCH (p:Principal)-[:CAN_PERFORM]->(a:Action)
WHERE a.is_high_privilege = true
RETURN p, a LIMIT 30

-- Show RSL-01 chain: PassRole + Lambda
MATCH (p:Principal)-[:CAN_PERFORM]->(a1:Action {name: 'iam:PassRole'})
MATCH (p)-[:CAN_PERFORM]->(a2:Action {name: 'lambda:CreateFunction'})
RETURN p, a1, a2

-- Show risk scores on principals
MATCH (p:Principal) WHERE p.risk_score IS NOT NULL
RETURN p.name, p.risk_score ORDER BY p.risk_score DESC
```

---

## Algorithm Documentation (Kill-Switch)

The rate detector uses **EWMA (Exponentially Weighted Moving Average)** — a
standard statistical threshold test. This is NOT machine learning, and is
not described as such anywhere in the codebase.

### How it works

Each IAM principal maintains its own baseline in DynamoDB:
- `ewma_rate`: rolling estimate of per-minute PUT/DELETE count
- `ewma_var`: rolling estimate of variance

Update rule (α = 0.3):
```
new_ewma_rate = α × window_count + (1 − α) × old_ewma_rate
new_ewma_var  = (1 − α) × (old_ewma_var + α × (window_count − old_ewma_rate)²)
```

Detection triggers when **either** condition is met:
1. `z_score = (window_count − ewma_rate) / sqrt(ewma_var) > 4.0`
2. `window_count > 10 × ewma_rate`

The z-score threshold catches principals whose current window is statistically
abnormal relative to their own history. The rate multiplier catches new
principals (few observations, unstable variance) who suddenly spike.

Cold-start protection: no flagging until `MIN_OBSERVATIONS = 5` windows
have been completed (prevents false positives during warm-up).

### Why principal-specific, not global

A principal that normally processes 500 objects/min will not be flagged at the
same absolute threshold as one that normally does 5/min. Each principal's
baseline is independent. The attacker.py simulator includes a `--mode seed-baseline`
to demonstrate this: seed a high-rate baseline, then attack at the same absolute
rate that flagged a low-baseline principal — no false positive.

---

## IAM Escalation Chain Reference

Chains are sourced from:
> *"AWS IAM Privilege Escalation – Methods and Mitigation"*
> Rhino Security Labs — https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

| Chain ID | Required Actions | MITRE ATT&CK |
|---|---|---|
| RSL-01 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | T1548 |
| RSL-02 | `iam:PassRole` + `ec2:RunInstances` | T1578 |
| RSL-03 | `iam:CreatePolicyVersion` | T1098 |
| RSL-04 | `iam:SetDefaultPolicyVersion` | T1098 |
| RSL-05 | `iam:AttachUserPolicy` (or equivalent) | T1098 |
| RSL-06 | `sts:AssumeRole` (no Condition) on admin-equivalent role | T1548 |

These patterns flag **combinations**, not individual permissions. Holding
`iam:PassRole` alone does not trigger RSL-01.

---

## Teardown

When done with the demo:

```powershell
python infra/teardown.py           # show what will be deleted
python infra/teardown.py --confirm # actually delete
docker compose down -v             # stop Neo4j and wipe graph data
```

This removes all AWS resources to prevent ongoing charges.

---

## Repository Layout

```
cloud-killswitch/
├── common/
│   └── attack_mapping.py      # Shared MITRE ATT&CK technique taxonomy
├── detector/
│   └── rate_monitor.py        # Lambda handler — EWMA detector (Phase 2)
├── remediator/
│   └── revoke.py              # Severity-tiered IAM remediation (Phase 2)
├── simulator/
│   └── attacker.py            # Controlled attack tool (Phase 2)
├── iam_graph/
│   ├── ingest.py              # IAM policy pull (Phase 3)
│   ├── graph_builder.py       # Neo4j graph construction (Phase 3)
│   ├── patterns.py            # Escalation chain detection — RSL-01–06 (Phase 3)
│   ├── risk_score.py          # Path + blast-radius scoring (Phase 3)
│   ├── escalation_test.py     # ⛔ Phase 4 — NOT BUILT (NotImplementedError)
│   └── remediate.py           # ⛔ Phase 4 — NOT BUILT (NotImplementedError)
├── infra/
│   ├── setup.py               # Provision all AWS resources
│   ├── teardown.py            # Destroy all resources
│   └── verify_pipeline.py     # Phase 1 acceptance test
├── reports/                   # Generated risk reports (gitignored)
├── docker-compose.yml         # Neo4j 5.x local instance
├── requirements.txt
├── .env.example
└── README.md
```

---

## Security Notes

- The attacker IAM user (`killswitch-attacker`) has access to **only** the test bucket.
  It cannot touch any other AWS resource.
- The Lambda execution role is scoped to only the resources it needs
  (test DynamoDB table, SNS topic, test user's IAM keys).
- The deny policy names are prefixed `killswitch-deny-*` for easy identification.
  After a demo, verify no unexpected deny policies remain: 
  `aws iam list-user-policies --user-name killswitch-attacker`
- Run teardown.py after every demo session.
