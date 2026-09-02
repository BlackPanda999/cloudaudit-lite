# CloudAudit Lite — Multi-Cloud Security Posture Scanner

A lightweight, dependency-free Python tool that audits AWS, Azure, and GCP cloud inventory for common security misconfigurations. No cloud credentials needed — you export your inventory as JSON and the tool scans it locally.

## Why

Cloud misconfigurations cause more breaches than exploits. Public storage, open firewalls, missing encryption, wildcard IAM policies — these are all config mistakes, not zero-days. CloudAudit Lite catches them before someone else does.

## Features

1. Multi-cloud support: AWS, Azure, and GCP
2. 27 checks across storage, IAM, network, database, compute, and logging
3. No external dependencies (pure Python 3)
4. No cloud credentials required (reads exported JSON inventory)
5. Text and JSON output formats
6. Security grade scoring (A-F)
7. CI/CD integration via exit codes (1 = HIGH/CRITICAL found)
8. Remediation advice for every finding

## Quick Start

```bash
# AWS
python cloudaudit.py --cloud aws --inventory inventory.json

# Azure
python cloudaudit.py --cloud azure --inventory inventory.json

# GCP
python cloudaudit.py --cloud gcp --inventory inventory.json

# JSON output
python cloudaudit.py --cloud aws --inventory inventory.json --format json

# Save report
python cloudaudit.py --cloud aws --inventory inventory.json --output report.json
```

## Checks

### AWS (13 checks)
1. S3 public access (CRITICAL)
2. S3 missing encryption (HIGH)
3. S3 no versioning (MEDIUM)
4. IAM wildcard policies (HIGH)
5. IAM old access keys (MEDIUM/HIGH)
6. Security group open SSH (HIGH)
7. Security group open RDP (CRITICAL)
8. Security group open all ports (CRITICAL)
9. RDS public accessibility (CRITICAL)
10. RDS missing encryption (HIGH)
11. CloudTrail disabled (MEDIUM)
12. Root MFA disabled (CRITICAL)
13. EC2 public IP (MEDIUM)

### Azure (7 checks)
1. Storage public blob access (CRITICAL)
2. Storage missing encryption (HIGH)
3. NSG open SSH (HIGH)
4. NSG open RDP (CRITICAL)
5. SQL firewall allow all (CRITICAL)
6. Custom role wildcard permissions (MEDIUM)
7. Disk missing encryption (HIGH)

### GCP (7 checks)
1. GCS bucket public access (CRITICAL)
2. GCS bucket no versioning (LOW)
3. Firewall open SSH (HIGH)
4. Firewall open all ports (CRITICAL)
5. IAM public role binding (CRITICAL)
6. Cloud SQL public IP (HIGH)
7. Disk missing encryption (HIGH)

## Inventory Format

Create a JSON file matching your cloud provider's structure. See `sample_aws_inventory.json` for an example.

### AWS Example
```json
{
    "s3_buckets": [
        {"name": "my-bucket", "public_access": false, "encryption": true, "versioning": true}
    ],
    "iam_roles": [
        {"name": "my-role", "policies": [{"statements": [{"Action": ["s3:GetObject"], "Effect": "Allow"}]}]}
    ],
    "security_groups": [
        {"name": "web-sg", "ingress_rules": [{"port": 443, "cidr": "0.0.0.0/0"}]}
    ],
    "rds_instances": [
        {"name": "my-db", "publicly_accessible": false, "encrypted": true}
    ],
    "ec2_instances": [
        {"name": "web-1", "id": "i-123", "public_ip": null}
    ],
    "cloudtrail_enabled": true,
    "root_mfa_enabled": true
}
```

## CI/CD Integration

The tool exits with code 1 if any CRITICAL or HIGH findings are detected, making it easy to plug into pipelines:

```yaml
# GitHub Actions example
- name: Cloud Security Audit
  run: python cloudaudit.py --cloud aws --inventory inventory.json --format json --output report.json
```

## Grading

| Grade | Score |
|-------|-------|
| A | 90-100% |
| B | 80-89% |
| C | 70-79% |
| D | 60-69% |
| F | Below 60% |

Score is calculated by subtracting weighted findings from the total. CRITICAL = 4 pts, HIGH = 3, MEDIUM = 2, LOW = 1.

## License

MIT — Free to use, modify, and share.

## Author

BlackPanda999 — https://github.com/BlackPanda999
