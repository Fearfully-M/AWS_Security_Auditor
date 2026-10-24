from rich import print
from report_generator import generate_csv_report, generate_html_report
import csv
from datetime import datetime as dt
from pathlib import Path

def test_write_file(tmp_path):
    output_path = tmp_path / "report.csv"

    findings = [
    {
        "domain": "SecurityGroup",
        "resource_id": "sg-123-range (ssh-public)",
        "severity": "High",
        "threat_type": "Source Vulnerability and Port Vulnerability",
        "explanation": "A port is publicy exposed due to CidrIp being set to '0.0.0.0/0'",
        "recommendation": "",
    },
    {
        "domain": "EC2",
        "resource_id": "i-bad",
        "severity": "Low",
        "threat_type": "Missing EC2 Instance tags",
        "explanation": "Instance i-bad has no name tag.",
        "recommendation": "NA",
    },
    {
        "domain": "IAM/MFA",
        "resource_id": "john.doe",
        "severity": "Medium",
        "threat_type": "MFA Not Enabled",
        "explanation": "IAM user john.doe does not have anMFA device configured.",
        "recommendation": "Enable MFA for this IAM User",
    },
    {
        "domain": "S3",
        "resource_id": "bucket-a",
        "severity": "Medium",
        "threat_type": "Block Public Access Disabled",
        "explanation": "Bucket has a private policy. Block Public Access is disabled.",
        "recommendation": "",
    },
]

    generate_csv_report(findings, output_path)

    with open(output_path, newline="") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    assert len(rows) == 4
    assert rows[0]["domain"] == "SecurityGroup"
    assert rows[0]["resource_id"] == "sg-123-range (ssh-public)"
    assert rows[0]["severity"] == "High"

    assert rows[1]["domain"] == "EC2"
    assert rows[1]["resource_id"] == "i-bad"
    assert rows[1]["severity"] == "Low"

    assert rows[2]["domain"] == "IAM/MFA"
    assert rows[2]["resource_id"] == "john.doe"
    assert rows[2]["severity"] == "Medium"

    assert rows[3]["domain"] == "S3"
    assert rows[3]["resource_id"] == "bucket-a"
    assert rows[3]["severity"] == "Medium"