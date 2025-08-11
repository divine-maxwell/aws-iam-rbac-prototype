#!/usr/bin/env python3
import os, json, time, io
from datetime import datetime
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*args, **kwargs): return False

def new_session(profile, region):
    return boto3.Session(profile_name=profile, region_name=region)

def assume_role(base_sess, role_arn, session_name):
    sts = base_sess.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=base_sess.region_name,
    )

def ensure_bucket(s3_client, bucket, region):
    try:
        s3_client.head_bucket(Bucket=bucket)
        return "exists"
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code in ("404", "NoSuchBucket", "404 Not Found", "NotFound"):
            pass
        else:
            # Could be 403 (exists but not owned by you)
            raise
    # Create bucket (region-aware)
    params = {"Bucket": bucket}
    if region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3_client.create_bucket(**params)
    # small wait for consistency
    waiter = s3_client.get_waiter("bucket_exists")
    waiter.wait(Bucket=bucket)
    return "created"

def try_s3_list(s3_client, bucket):
    try:
        s3_client.list_objects_v2(Bucket=bucket, MaxKeys=5)
        return True, ""
    except ClientError as e:
        return False, e.response["Error"]["Code"]

def try_s3_put(s3_client, bucket, key, body):
    try:
        s3_client.put_object(Bucket=bucket, Key=key, Body=body)
        return True, ""
    except ClientError as e:
        return False, e.response["Error"]["Code"]

def try_ec2_describe(ec2_client):
    try:
        ec2_client.describe_instances(MaxResults=5)
        return True, ""
    except ClientError as e:
        return False, e.response["Error"]["Code"]

def try_ec2_start_dryrun(ec2_client):
    # DryRun returns:
    #  - DryRunOperation if you WOULD be allowed
    #  - UnauthorizedOperation if you are NOT allowed
    try:
        ec2_client.start_instances(InstanceIds=["i-0abcdef0123456789"], DryRun=True)
        return True, ""  # unlikely, but treat as allowed
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "DryRunOperation":
            return True, code
        return False, code

def main():
    load_dotenv()
    profile = os.getenv("AWS_PROFILE", "rbac-lab")
    region = os.getenv("AWS_REGION", "ca-central-1")
    account = os.getenv("ACCOUNT_ID")
    bucket = os.getenv("BUCKET_NAME")
    if not (account and bucket):
        raise SystemExit("ACCOUNT_ID and BUCKET_NAME must be set in .env")

    base = new_session(profile, region)
    iam = base.client("iam")
    # Build role ARNs
    roles = {
        "Admin":     f"arn:aws:iam::{account}:role/dm-rbac-Admin",
        "Developer": f"arn:aws:iam::{account}:role/dm-rbac-Developer",
        "ReadOnly":  f"arn:aws:iam::{account}:role/dm-rbac-ReadOnly",
    }

    # Ensure bucket exists via Admin role (by design Developer/ReadOnly can't create)
    admin_sess = assume_role(base, roles["Admin"], "AdminSetup")
    admin_s3 = admin_sess.client("s3")
    status = ensure_bucket(admin_s3, bucket, region)

    tests = []
    for tier, role_arn in roles.items():
        sess = assume_role(base, role_arn, f"{tier}Session")
        s3 = sess.client("s3")
        ec2 = sess.client("ec2")

        # S3 list
        ok_list, err_list = try_s3_list(s3, bucket)
        # S3 put
        key = f"test/{tier.lower()}-{int(time.time())}.txt"
        ok_put, err_put = try_s3_put(s3, bucket, key, f"hello from {tier}".encode())

        # EC2 describe
        ok_desc, err_desc = try_ec2_describe(ec2)
        # EC2 start (dry run)
        ok_start, err_start = try_ec2_start_dryrun(ec2)

        tests.append({
            "tier": tier,
            "s3_list": ok_list, "s3_list_err": err_list,
            "s3_put": ok_put, "s3_put_err": err_put,
            "ec2_describe": ok_desc, "ec2_desc_err": err_desc,
            "ec2_start_dryrun": ok_start, "ec2_start_err": err_start,
        })

    # Print table
    rows = []
    for t in tests:
        rows.append([
            t["tier"],
            "PASS" if t["s3_list"] else f"FAIL({t['s3_list_err']})",
            "PASS" if t["s3_put"] else f"FAIL({t['s3_put_err']})",
            "PASS" if t["ec2_describe"] else f"FAIL({t['ec2_desc_err']})",
            "PASS" if t["ec2_start_dryrun"] else f"FAIL({t['ec2_start_err']})",
        ])
    print(f"\nS3 bucket ensure status: {status}")
    print(tabulate(rows, headers=["Role","S3 ListBucket","S3 PutObject","EC2 Describe","EC2 Start (DryRun)"], tablefmt="github"))

    # Save CSV for your repo
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    outdir = Path("docs/runs"); outdir.mkdir(parents=True, exist_ok=True)
    csv_path = outdir / f"rbac_test_{timestamp}.csv"
    with csv_path.open("w", encoding="utf-8") as f:
        f.write("role,s3_list,s3_put,ec2_describe,ec2_start_dryrun\n")
        for t in tests:
            f.write(f"{t['tier']},{t['s3_list']},{t['s3_put']},{t['ec2_describe']},{t['ec2_start_dryrun']}\n")
    print(f"\nSaved report: {csv_path}")
    print(f"Account: {account} | Region: {region} | Bucket: {bucket}")

if __name__ == "__main__":
    main()

