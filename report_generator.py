import csv
from rich import print
from rich.console import Console
from rich.table import Table
from rich.text import Text
from datetime import datetime as dt
from pathlib import Path

# takes security auditor findings and saves them into a CSV
def generate_csv_report(findings, report_file=None):
    if report_file is None:
        output_dir = Path("reports/")
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = dt.now().strftime(f"SecurityAuditorResults_%Y-%m-%d_%H-%M-%S.csv")

        report_file = output_dir / filename
    
    with open(report_file, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["domain", "resource_id", "severity","threat_type", "explanation", "recommendation"]
        )

        writer.writeheader()
        writer.writerows(findings)

    console = Console()
    table = Table(title="Security Findings Report")

    # columns
    headers = [
      "Domain",
      "Resource ID",
      "Severity",
      "Threat Type",
      "Explanation",
      "Recommendation",
  ]

    # columns
    for header in headers:
        table.add_column(header, style ="green" if header == "Domain" else "white")

    # rows
    for row in findings:
        severity_value = str(row.get("severity", ""))

        if severity_value == 'High':
            severity_cell = Text(severity_value, style = "bold red")
        elif severity_value == 'Medium':
            severity_cell = Text(severity_value, style = "yellow")
        elif severity_value == 'Low':
            severity_cell = Text(severity_value, style = "blue")
        else:
            severity_cell = Text(severity_value, style = "red")

        table.add_row(
            str(row.get("domain", "")),
            str(row.get("resource_id", "")),
            severity_cell,
            str(row.get("threat_type", "")),
            str(row.get("explanation", "")),
            str(row.get("recommendation", "")),
    )

    console.print(table)

    

# takes security auditor findings and saves them into an HTML
def generate_html_report(findings):
    ...


concatenated_findings = [
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

generate_html_report(concatenated_findings)