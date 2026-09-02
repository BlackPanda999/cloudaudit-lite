#!/usr/bin/env python3
"""
CloudAudit Lite — Multi-Cloud Security Posture Scanner
Scans AWS, Azure, and GCP inventory JSON files for common misconfigurations.
No cloud credentials needed. No external dependencies. Pure Python.

Usage:
    python cloudaudit.py --cloud aws --inventory inventory.json
    python cloudaudit.py --cloud azure --inventory inventory.json
    python cloudaudit.py --cloud gcp --inventory inventory.json
    python cloudaudit.py --cloud aws --inventory inventory.json --format json
    python cloudaudit.py --cloud aws --inventory inventory.json --output report.json
"""

import argparse
import json
import os
import sys
from datetime import datetime


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class Finding:
    def __init__(self, check_id, severity, category, resource, message, remediation):
        self.check_id = check_id
        self.severity = severity
        self.category = category
        self.resource = resource
        self.message = message
        self.remediation = remediation

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "category": self.category,
            "resource": self.resource,
            "message": self.message,
            "remediation": self.remediation,
        }


# ============================================================
# AWS CHECKS
# ============================================================

def check_aws_s3_public_buckets(inventory, findings):
    for bucket in inventory.get("s3_buckets", []):
        if bucket.get("public_access") in [True, "True", "true"]:
            findings.append(Finding(
                "AWS-S3-001", "CRITICAL", "Storage",
                bucket.get("name", "unknown"),
                "S3 bucket has public access enabled",
                "Disable public access block and set bucket ACL to private"
            ))


def check_aws_s3_encryption(inventory, findings):
    for bucket in inventory.get("s3_buckets", []):
        if not bucket.get("encryption"):
            findings.append(Finding(
                "AWS-S3-002", "HIGH", "Storage",
                bucket.get("name", "unknown"),
                "S3 bucket has no encryption enabled",
                "Enable SSE-S3 or SSE-KMS encryption on the bucket"
            ))


def check_aws_s3_versioning(inventory, findings):
    for bucket in inventory.get("s3_buckets", []):
        if not bucket.get("versioning"):
            findings.append(Finding(
                "AWS-S3-003", "MEDIUM", "Storage",
                bucket.get("name", "unknown"),
                "S3 bucket has versioning disabled",
                "Enable versioning to protect against accidental deletion"
            ))


def check_aws_iam_wildcard_policies(inventory, findings):
    for role in inventory.get("iam_roles", []):
        for policy in role.get("policies", []):
            for stmt in policy.get("statements", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    if action == "*" or action == "*:*":
                        findings.append(Finding(
                            "AWS-IAM-001", "HIGH", "IAM",
                            role.get("name", "unknown"),
                            f"IAM role has wildcard action: {action}",
                            "Replace wildcard with specific actions following least privilege"
                        ))


def check_aws_iam_old_keys(inventory, findings):
    for key in inventory.get("iam_access_keys", []):
        age = key.get("age_days", 0)
        if age > 90:
            sev = "HIGH" if age > 365 else "MEDIUM"
            findings.append(Finding(
                "AWS-IAM-002", sev, "IAM",
                key.get("user", "unknown"),
                f"Access key is {age} days old (max recommended: 90)",
                "Rotate the access key and deactivate the old one"
            ))


def check_aws_sg_open_ssh(inventory, findings):
    for sg in inventory.get("security_groups", []):
        for rule in sg.get("ingress_rules", []):
            if rule.get("port") in [22, "22"] and rule.get("cidr") in ["0.0.0.0/0", "::/0"]:
                findings.append(Finding(
                    "AWS-SG-001", "HIGH", "Network",
                    sg.get("name", "unknown"),
                    "Security group allows SSH (port 22) from 0.0.0.0/0",
                    "Restrict SSH to specific IPs or use a bastion/VPN"
                ))


def check_aws_sg_open_rdp(inventory, findings):
    for sg in inventory.get("security_groups", []):
        for rule in sg.get("ingress_rules", []):
            if rule.get("port") in [3389, "3389"] and rule.get("cidr") in ["0.0.0.0/0", "::/0"]:
                findings.append(Finding(
                    "AWS-SG-002", "CRITICAL", "Network",
                    sg.get("name", "unknown"),
                    "Security group allows RDP (port 3389) from 0.0.0.0/0",
                    "Restrict RDP to specific IPs or use a VPN"
                ))


def check_aws_sg_open_all(inventory, findings):
    for sg in inventory.get("security_groups", []):
        for rule in sg.get("ingress_rules", []):
            if rule.get("port") in [0, "0", "-1", "all"] and rule.get("cidr") in ["0.0.0.0/0", "::/0"]:
                findings.append(Finding(
                    "AWS-SG-003", "CRITICAL", "Network",
                    sg.get("name", "unknown"),
                    "Security group allows ALL traffic from 0.0.0.0/0",
                    "Remove the rule and apply specific port/IP restrictions"
                ))


def check_aws_rds_public(inventory, findings):
    for db in inventory.get("rds_instances", []):
        if db.get("publicly_accessible"):
            findings.append(Finding(
                "AWS-RDS-001", "CRITICAL", "Database",
                db.get("name", "unknown"),
                "RDS instance is publicly accessible",
                "Set publicly_accessible to false"
            ))


def check_aws_rds_encryption(inventory, findings):
    for db in inventory.get("rds_instances", []):
        if not db.get("encrypted"):
            findings.append(Finding(
                "AWS-RDS-002", "HIGH", "Database",
                db.get("name", "unknown"),
                "RDS instance has no encryption at rest",
                "Enable storage encryption on the RDS instance"
            ))


def check_aws_cloudtrail(inventory, findings):
    if not inventory.get("cloudtrail_enabled", True):
        findings.append(Finding(
            "AWS-LOG-001", "MEDIUM", "Logging",
            "account-level",
            "CloudTrail logging appears to be disabled",
            "Enable CloudTrail for audit logging"
        ))


def check_aws_root_mfa(inventory, findings):
    if not inventory.get("root_mfa_enabled", True):
        findings.append(Finding(
            "AWS-IAM-003", "CRITICAL", "IAM",
            "root-account",
            "Root account does not have MFA enabled",
            "Enable MFA on the root account immediately"
        ))


def check_aws_ec2_public_ip(inventory, findings):
    for instance in inventory.get("ec2_instances", []):
        if instance.get("public_ip"):
            findings.append(Finding(
                "AWS-EC2-001", "MEDIUM", "Compute",
                instance.get("name", instance.get("id", "unknown")),
                "EC2 instance has a public IP assigned",
                "Remove public IP if not needed, place behind a load balancer"
            ))


# ============================================================
# AZURE CHECKS
# ============================================================

def check_azure_storage_public(inventory, findings):
    for account in inventory.get("storage_accounts", []):
        if account.get("allow_public_blob"):
            findings.append(Finding(
                "AZ-STOR-001", "CRITICAL", "Storage",
                account.get("name", "unknown"),
                "Storage account allows public blob access",
                "Disable allow_blob_public_access"
            ))


def check_azure_storage_encryption(inventory, findings):
    for account in inventory.get("storage_accounts", []):
        if not account.get("encryption_enabled"):
            findings.append(Finding(
                "AZ-STOR-002", "HIGH", "Storage",
                account.get("name", "unknown"),
                "Storage account has no encryption enabled",
                "Enable Microsoft-managed or customer-managed encryption"
            ))


def check_azure_nsg_open_ssh(inventory, findings):
    for nsg in inventory.get("network_security_groups", []):
        for rule in nsg.get("rules", []):
            if rule.get("port") in [22, "22", "*"] and rule.get("source") in ["*", "0.0.0.0/0", "any"]:
                findings.append(Finding(
                    "AZ-NSG-001", "HIGH", "Network",
                    nsg.get("name", "unknown"),
                    "NSG allows SSH from any source",
                    "Restrict to specific source IPs"
                ))


def check_azure_nsg_open_rdp(inventory, findings):
    for nsg in inventory.get("network_security_groups", []):
        for rule in nsg.get("rules", []):
            if rule.get("port") in [3389, "3389", "*"] and rule.get("source") in ["*", "0.0.0.0/0", "any"]:
                findings.append(Finding(
                    "AZ-NSG-002", "CRITICAL", "Network",
                    nsg.get("name", "unknown"),
                    "NSG allows RDP from any source",
                    "Restrict to specific source IPs"
                ))


def check_azure_sql_public(inventory, findings):
    for server in inventory.get("sql_servers", []):
        if server.get("firewall_allow_all"):
            findings.append(Finding(
                "AZ-SQL-001", "CRITICAL", "Database",
                server.get("name", "unknown"),
                "SQL server firewall allows all traffic (0.0.0.0-255.255.255.255)",
                "Restrict firewall rules to specific IP ranges"
            ))


def check_azure_iam_custom_roles(inventory, findings):
    for role in inventory.get("custom_roles", []):
        if "*" in str(role.get("permissions", [])):
            findings.append(Finding(
                "AZ-IAM-001", "MEDIUM", "IAM",
                role.get("name", "unknown"),
                "Custom role has wildcard permissions",
                "Scope permissions to specific actions"
            ))


def check_azure_disk_encryption(inventory, findings):
    for disk in inventory.get("disks", []):
        if not disk.get("encrypted"):
            findings.append(Finding(
                "AZ-DISK-001", "HIGH", "Compute",
                disk.get("name", "unknown"),
                "Managed disk has no encryption",
                "Enable Azure Disk Encryption (ADE)"
            ))


# ============================================================
# GCP CHECKS
# ============================================================

def check_gcp_bucket_public(inventory, findings):
    for bucket in inventory.get("storage_buckets", []):
        if bucket.get("public"):
            findings.append(Finding(
                "GCP-BKT-001", "CRITICAL", "Storage",
                bucket.get("name", "unknown"),
                "GCS bucket is publicly accessible",
                "Set uniform bucket-level access and remove public ACLs"
            ))


def check_gcp_bucket_versioning(inventory, findings):
    for bucket in inventory.get("storage_buckets", []):
        if not bucket.get("versioning"):
            findings.append(Finding(
                "GCP-BKT-002", "LOW", "Storage",
                bucket.get("name", "unknown"),
                "GCS bucket has no versioning",
                "Enable bucket versioning"
            ))


def check_gcp_firewall_open_ssh(inventory, findings):
    for rule in inventory.get("firewall_rules", []):
        if rule.get("port") in [22, "22"] and rule.get("source_ranges"):
            for r in rule["source_ranges"]:
                if r == "0.0.0.0/0":
                    findings.append(Finding(
                        "GCP-FW-001", "HIGH", "Network",
                        rule.get("name", "unknown"),
                        "Firewall rule allows SSH from 0.0.0.0/0",
                        "Restrict to specific IP ranges"
                    ))


def check_gcp_firewall_open_all(inventory, findings):
    for rule in inventory.get("firewall_rules", []):
        if rule.get("source_ranges") and "0.0.0.0/0" in rule["source_ranges"]:
            ports = rule.get("ports", [])
            if not ports or "all" in ports or "0-65535" in ports:
                findings.append(Finding(
                    "GCP-FW-002", "CRITICAL", "Network",
                    rule.get("name", "unknown"),
                    "Firewall rule allows all ports from 0.0.0.0/0",
                    "Restrict ports and source ranges"
                ))


def check_gcp_iam_wildcard(inventory, findings):
    for binding in inventory.get("iam_bindings", []):
        role = binding.get("role", "")
        if "admin" in role.lower() or "owner" in role.lower():
            members = binding.get("members", [])
            for m in members:
                if m.startswith("allUsers") or m.startswith("allAuthenticatedUsers"):
                    findings.append(Finding(
                        "GCP-IAM-001", "CRITICAL", "IAM",
                        role,
                        f"Role {role} granted to {m}",
                        "Remove public bindings and assign to specific service accounts"
                    ))


def check_gcp_sql_public(inventory, findings):
    for instance in inventory.get("sql_instances", []):
        if instance.get("public_ip"):
            findings.append(Finding(
                "GCP-SQL-001", "HIGH", "Database",
                instance.get("name", "unknown"),
                "Cloud SQL instance has a public IP",
                "Use private IP or remove external access"
            ))


def check_gcp_disk_encryption(inventory, findings):
    for disk in inventory.get("disks", []):
        if not disk.get("encrypted"):
            findings.append(Finding(
                "GCP-DISK-001", "HIGH", "Compute",
                disk.get("name", "unknown"),
                "Persistent disk has no encryption",
                "Enable CMEK or use Google-managed encryption keys"
            ))


# ============================================================
# RUNNER
# ============================================================

AWS_CHECKS = [
    check_aws_s3_public_buckets, check_aws_s3_encryption, check_aws_s3_versioning,
    check_aws_iam_wildcard_policies, check_aws_iam_old_keys, check_aws_sg_open_ssh,
    check_aws_sg_open_rdp, check_aws_sg_open_all, check_aws_rds_public,
    check_aws_rds_encryption, check_aws_cloudtrail, check_aws_root_mfa,
    check_aws_ec2_public_ip,
]

AZURE_CHECKS = [
    check_azure_storage_public, check_azure_storage_encryption,
    check_azure_nsg_open_ssh, check_azure_nsg_open_rdp,
    check_azure_sql_public, check_azure_iam_custom_roles,
    check_azure_disk_encryption,
]

GCP_CHECKS = [
    check_gcp_bucket_public, check_gcp_bucket_versioning,
    check_gcp_firewall_open_ssh, check_gcp_firewall_open_all,
    check_gcp_iam_wildcard, check_gcp_sql_public,
    check_gcp_disk_encryption,
]


def run_audit(cloud, inventory):
    findings = []
    checks = {"aws": AWS_CHECKS, "azure": AZURE_CHECKS, "gcp": GCP_CHECKS}
    check_list = checks.get(cloud, [])
    for check in check_list:
        try:
            check(inventory, findings)
        except Exception as e:
            findings.append(Finding(
                "META-ERR", "INFO", "Internal",
                check.__name__,
                f"Check skipped due to error: {str(e)}",
                "Review the inventory file format"
            ))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings


def grade(score, total):
    if total == 0:
        return "A"
    pct = (score / total) * 100
    if pct >= 90:
        return "A"
    elif pct >= 80:
        return "B"
    elif pct >= 70:
        return "C"
    elif pct >= 60:
        return "D"
    else:
        return "F"


def print_report(findings, cloud):
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    total = len(findings)
    score = total - (severity_counts["CRITICAL"] * 4 + severity_counts["HIGH"] * 3 +
                     severity_counts["MEDIUM"] * 2 + severity_counts["LOW"] * 1)
    score = max(0, score)
    g = grade(score, max(total, 1))

    print(f"\n{'='*60}")
    print(f"  CloudAudit Lite — {cloud.upper()} Security Report")
    print(f"{'='*60}")
    print(f"  Scanned: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Total findings: {total}")
    print(f"  Grade: {g}")
    print(f"{'='*60}\n")

    print("  Severity Breakdown:")
    print(f"    CRITICAL: {severity_counts['CRITICAL']}")
    print(f"    HIGH:     {severity_counts['HIGH']}")
    print(f"    MEDIUM:   {severity_counts['MEDIUM']}")
    print(f"    LOW:      {severity_counts['LOW']}")
    print(f"    INFO:     {severity_counts['INFO']}")
    print()

    if not findings:
        print("  No misconfigurations found. Nice!\n")
        return

    for f in findings:
        print(f"  [{f.severity}] {f.check_id}")
        print(f"    Resource: {f.resource}")
        print(f"    Issue:    {f.message}")
        print(f"    Fix:      {f.remediation}")
        print()

    print(f"{'='*60}")
    print(f"  {total} findings | Grade: {g}")
    print(f"{'='*60}\n")


def json_report(findings, cloud):
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    total = len(findings)
    score = max(0, total - (severity_counts["CRITICAL"] * 4 + severity_counts["HIGH"] * 3 +
                           severity_counts["MEDIUM"] * 2 + severity_counts["LOW"] * 1))
    return {
        "tool": "CloudAudit Lite",
        "cloud": cloud,
        "scan_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "grade": grade(score, max(total, 1)),
        "total_findings": total,
        "severity_counts": severity_counts,
        "findings": [f.to_dict() for f in findings],
    }


def main():
    parser = argparse.ArgumentParser(
        description="CloudAudit Lite — Multi-Cloud Security Posture Scanner"
    )
    parser.add_argument("--cloud", required=True, choices=["aws", "azure", "gcp"],
                        help="Cloud provider to audit")
    parser.add_argument("--inventory", required=True, help="Path to inventory JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", help="Save report to file")
    args = parser.parse_args()

    if not os.path.exists(args.inventory):
        print(f"Error: Inventory file not found: {args.inventory}")
        sys.exit(2)

    with open(args.inventory) as f:
        inventory = json.load(f)

    findings = run_audit(args.cloud, inventory)

    if args.format == "json":
        report = json_report(findings, args.cloud)
        output = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        print_report(findings, args.cloud)
        if args.output:
            report = json_report(findings, args.cloud)
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"JSON report also saved to {args.output}")

    has_high = any(f.severity in ["CRITICAL", "HIGH"] for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
