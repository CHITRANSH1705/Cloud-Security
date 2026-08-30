"""
common/attack_mapping.py

Shared MITRE ATT&CK Cloud Matrix technique taxonomy used by BOTH modules:
  - Kill-Switch (detector + remediator) tags each finding with a technique ID
  - IAM Permission Graph tags each escalation chain with a technique ID

This ensures every finding from either module is expressed in the same vocabulary,
making findings correlatable across modules.

Reference: MITRE ATT&CK Cloud Matrix
https://attack.mitre.org/matrices/enterprise/cloud/

Usage:
    from common.attack_mapping import TECHNIQUES, tag_finding

    technique = TECHNIQUES["DATA_DESTRUCTION"]
    finding = tag_finding({"principal": "..."}, "DATA_DESTRUCTION")
"""

from __future__ import annotations
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Technique Registry
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUES: dict[str, dict[str, str]] = {
    # ── Kill-Switch techniques ────────────────────────────────────────────────

    "DATA_DESTRUCTION": {
        "id":          "T1485",
        "name":        "Data Destruction",
        "url":         "https://attack.mitre.org/techniques/T1485/",
        "description": "Adversary destroys data to interrupt availability. "
                       "In S3 context: abnormal bulk DeleteObject calls.",
        "tactic":      "Impact",
        "module":      "kill-switch",
    },

    "DATA_DESTRUCTION_LIFECYCLE": {
        "id":          "T1485.001",
        "name":        "Data Destruction: Lifecycle-Triggered Deletion",
        "url":         "https://attack.mitre.org/techniques/T1485/001/",
        "description": "Adversary modifies S3 lifecycle policies to schedule "
                       "automated bulk deletion of objects.",
        "tactic":      "Impact",
        "module":      "kill-switch",
    },

    "DATA_ENCRYPTED_FOR_IMPACT": {
        "id":          "T1486",
        "name":        "Data Encrypted for Impact",
        "url":         "https://attack.mitre.org/techniques/T1486/",
        "description": "Adversary encrypts S3 objects (SSE-C or client-side) "
                       "to make them inaccessible and demand ransom.",
        "tactic":      "Impact",
        "module":      "kill-switch",
    },

    "VALID_ACCOUNTS_CLOUD": {
        "id":          "T1078.004",
        "name":        "Valid Accounts: Cloud Accounts",
        "url":         "https://attack.mitre.org/techniques/T1078/004/",
        "description": "Adversary uses compromised IAM credentials (user/role) "
                       "to perform malicious S3 operations.",
        "tactic":      "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "module":      "kill-switch",
    },

    # ── IAM Graph techniques ──────────────────────────────────────────────────

    "IAM_ACCOUNT_MANIPULATION": {
        "id":          "T1098",
        "name":        "Account Manipulation",
        "url":         "https://attack.mitre.org/techniques/T1098/",
        "description": "Adversary modifies IAM permissions (policy versions, "
                       "attached policies) to maintain or escalate access.",
        "tactic":      "Persistence",
        "module":      "iam-graph",
    },

    "PRIV_ESC_LAMBDA": {
        "id":          "T1548",
        "name":        "Abuse Elevation Control Mechanism",
        "url":         "https://attack.mitre.org/techniques/T1548/",
        "description": "Adversary abuses iam:PassRole + lambda:CreateFunction "
                       "to execute code under a higher-privileged role. "
                       "Source: Rhino Security Labs RSL-01.",
        "tactic":      "Privilege Escalation / Defense Evasion",
        "module":      "iam-graph",
    },

    "PRIV_ESC_EC2": {
        "id":          "T1578",
        "name":        "Modify Cloud Compute Infrastructure",
        "url":         "https://attack.mitre.org/techniques/T1578/",
        "description": "Adversary abuses iam:PassRole + ec2:RunInstances "
                       "to launch an EC2 instance under a privileged role. "
                       "Source: Rhino Security Labs RSL-02.",
        "tactic":      "Defense Evasion",
        "module":      "iam-graph",
    },

    "PRIV_ESC_POLICY_VERSION": {
        "id":          "T1098",
        "name":        "Account Manipulation (Policy Version)",
        "url":         "https://attack.mitre.org/techniques/T1098/",
        "description": "Adversary uses iam:CreatePolicyVersion to replace an "
                       "existing policy with an admin-granting version. "
                       "Source: Rhino Security Labs RSL-03.",
        "tactic":      "Persistence",
        "module":      "iam-graph",
    },

    "PRIV_ESC_SET_DEFAULT_VERSION": {
        "id":          "T1098",
        "name":        "Account Manipulation (Set Default Policy Version)",
        "url":         "https://attack.mitre.org/techniques/T1098/",
        "description": "Adversary uses iam:SetDefaultPolicyVersion to promote "
                       "a previously created permissive policy version. "
                       "Source: Rhino Security Labs RSL-04.",
        "tactic":      "Persistence",
        "module":      "iam-graph",
    },

    "PRIV_ESC_ATTACH_SELF_POLICY": {
        "id":          "T1098",
        "name":        "Account Manipulation (Self Policy Attach)",
        "url":         "https://attack.mitre.org/techniques/T1098/",
        "description": "Adversary uses iam:AttachUserPolicy on their own user "
                       "to attach AdministratorAccess or equivalent. "
                       "Source: Rhino Security Labs RSL-05.",
        "tactic":      "Persistence",
        "module":      "iam-graph",
    },

    "PRIV_ESC_ASSUME_ADMIN_ROLE": {
        "id":          "T1548",
        "name":        "Abuse Elevation Control Mechanism (Unconstrained AssumeRole)",
        "url":         "https://attack.mitre.org/techniques/T1548/",
        "description": "Adversary uses sts:AssumeRole on an admin-equivalent "
                       "role that has no Condition block restricting callers. "
                       "Source: Rhino Security Labs RSL-06.",
        "tactic":      "Privilege Escalation",
        "module":      "iam-graph",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def get_technique(key: str) -> dict[str, str]:
    """Return technique metadata by registry key, raising KeyError on miss."""
    if key not in TECHNIQUES:
        raise KeyError(
            f"Unknown technique key '{key}'. "
            f"Valid keys: {sorted(TECHNIQUES.keys())}"
        )
    return TECHNIQUES[key]


def tag_finding(finding: dict[str, Any], technique_key: str) -> dict[str, Any]:
    """
    Merge ATT&CK technique metadata into a finding dict.

    Example:
        finding = {"principal": "arn:aws:iam::123:user/attacker", "window_count": 87}
        tagged = tag_finding(finding, "DATA_DESTRUCTION")
        # tagged now contains "technique_id", "technique_name", "technique_url"
    """
    technique = get_technique(technique_key)
    return {
        **finding,
        "technique_key":  technique_key,
        "technique_id":   technique["id"],
        "technique_name": technique["name"],
        "technique_url":  technique["url"],
        "technique_tactic": technique["tactic"],
    }


def list_techniques_for_module(module: str) -> list[dict[str, str]]:
    """Return all techniques for a given module name ('kill-switch' or 'iam-graph')."""
    return [
        {"key": k, **v}
        for k, v in TECHNIQUES.items()
        if v.get("module") == module
    ]
