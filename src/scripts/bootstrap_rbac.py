#!/usr/bin/env python3
"""
IAM RBAC Prototype — Bootstrap
Creates customer-managed policies & roles:
  - dm-rbac-Admin / dm-rbac-AdminPolicy
  - dm-rbac-Developer / dm-rbac-DeveloperPolicy
  - dm-rbac-ReadOnly / dm-rbac-ReadOnlyPolicy
Then attaches the matching policy to each role.
"""

from __future__ import annotations
import argparse, json, os
from pathlib import Path
from typing import Dict, Tuple, Optional

import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*args, **kwargs): return False

PROJECT_PREFIX = os.environ.get("PROJECT_PREFIX", "dm-rbac")
TAGS = [
    {"Key": "Project", "Value": PROJECT_PREFIX},
    {"Key": "Owner", "Value": os.environ.get("OWNER_TAG", "DivineMaxwell")},
    {"Key": "Env", "Value": os.environ.get("ENV_TAG", "lab")},
]

POLICY_FILES = {
    "Admin": "admin-policy.json",
    "Developer": "developer-policy.json",
    "ReadOnly": "readonly-policy.json",
}

def load_policy_json(policy_dir: Path, filename: str) -> Dict:
    p = policy_dir / filename
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def session_from_args(profile: Optional[str], region: Optional[str]):
    load_dotenv()
    profile = profile or os.getenv("AWS_PROFILE", "rbac-lab")
    region = region or os.getenv("AWS_REGION", "ca-central-1")
    return boto3.Session(profile_name=profile, region_name=region)

def get_account_id(sts_client) -> str:
    return sts_client.get_caller_identity()["Account"]

def ensure_policy(iam, name: str, document: Dict) -> Tuple[str, bool]:
    """Return (policy_arn, created_flag). Looks up by name in local (customer) scope."""
    marker = None
    while True:
        kwargs = {"Scope": "Local"}
        if marker: kwargs["Marker"] = marker
        resp = iam.list_policies(**kwargs)
        for p in resp.get("Policies", []):
            if p.get("PolicyName") == name:
                return p["Arn"], False
        if resp.get("IsTruncated"): marker = resp.get("Marker")
        else: break

    create = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document), Tags=TAGS)
    return create["Policy"]["Arn"], True

def build_trust_policy_for_account(account_id: str) -> Dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole"
        }]
    }

def ensure_role(iam, name: str, trust: Dict, tags: list) -> Tuple[str, bool]:
    try:
        resp = iam.get_role(RoleName=name)
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
        return resp["Role"]["Arn"], False
    except ClientError as e:
        if e.response["Error"].get("Code") != "NoSuchEntity":
            raise
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=tags,
        Description=f"{PROJECT_PREFIX} lab role: {name}",
        MaxSessionDuration=3600,
    )
    return resp["Role"]["Arn"], True

def ensure_attachment(iam, role_name: str, policy_arn: str) -> bool:
    paginator = iam.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for ap in page.get("AttachedPolicies", []):
            if ap.get("PolicyArn") == policy_arn:
                return False
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return True

def main():
    parser = argparse.ArgumentParser(description="Bootstrap IAM RBAC roles & policies")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    session = session_from_args(args.profile, args.region)
    iam = session.client("iam")
    sts = session.client("sts")

    account_id = get_account_id(sts)
    trust = build_trust_policy_for_account(account_id)

    script_dir = Path(__file__).resolve().parent
    policy_dir = script_dir.parent / "policies"

    docs: Dict[str, Dict] = {k: load_policy_json(policy_dir, v) for k, v in POLICY_FILES.items()}

    # Ensure customer-managed policies
    policy_names = {
        "Admin":     f"{PROJECT_PREFIX}-AdminPolicy",
        "Developer": f"{PROJECT_PREFIX}-DeveloperPolicy",
        "ReadOnly":  f"{PROJECT_PREFIX}-ReadOnlyPolicy",
    }
    created = {}
    policy_arns = {}
    for tier, pname in policy_names.items():
        arn, was_created = ensure_policy(iam, pname, docs[tier])
        policy_arns[tier] = arn
        created[f"policy_{tier}"] = was_created

    # Ensure roles
    roles = {
        "Admin":     f"{PROJECT_PREFIX}-Admin",
        "Developer": f"{PROJECT_PREFIX}-Developer",
        "ReadOnly":  f"{PROJECT_PREFIX}-ReadOnly",
    }
    role_arns = {}
    for tier, rname in roles.items():
        r_arn, r_created = ensure_role(iam, rname, trust, TAGS)
        role_arns[tier] = r_arn
        created[f"role_{tier}"] = r_created

    # Attach
    for tier in roles.keys():
        attached_now = ensure_attachment(iam, roles[tier], policy_arns[tier])
        created[f"attach_{tier}"] = attached_now

    rows = []
    for tier in ("Admin","Developer","ReadOnly"):
        rows.append([
            tier,
            policy_names[tier],
            policy_arns[tier],
            roles[tier],
            role_arns[tier],
            "created" if created.get(f"role_{tier}") else "exists",
            "created" if created.get(f"policy_{tier}") else "exists",
            "attached" if created.get(f"attach_{tier}") else "already",
        ])
    print(tabulate(rows, headers=[
        "RBAC Tier","Policy Name","Policy ARN","Role Name","Role ARN",
        "Role Status","Policy Status","Attachment"
    ], tablefmt="github"))
    print(f"\nAccount: {account_id}  |  Region: {session.region_name}")

if __name__ == "__main__":
    main()
