from rich import print
from report_generator import generate_csv_report, generate_html_report
import csv
from html import escape

def test_write_file_csv(tmp_path):
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

def test_write_file_html(tmp_path):
    findings = [
     {
          "domain": "SecurityGroup",
          "resource_id": "sg-123",
          "severity": "High",
          "threat_type": "Port Vulnerability",
          # Include an unsafe-looking value with HTML tags to test escape()
          "explanation": (
              "A port is publicly exposed by user <admin> with <b>bad</b> config"
          ),
          "recommendation": "You need to fix it",
      }
  ]
    
    output_path = tmp_path / "report.html"

    # generate the HTML report
    generate_html_report(findings, output_path)

    html_content = output_path.read_text()

    # verify standard html structures
    assert "<html>" in html_content
    assert "<table>" in html_content

    # verify actual content is in the html file
    assert "<th>Domain</th>" in html_content
    assert "<th>Resource ID</th>" in html_content
    assert "<td>SecurityGroup</td>" in html_content
    assert "<td>High</td>" in html_content
    assert "<td>sg-123</td>" in html_content
    assert "SecurityGroup" in html_content
    assert "High" in html_content

    # raw rags shouldn't be in the html file
    assert "<admin>" not in html_content
    assert "<b>bad</b>" not in html_content

    # escaped entities should be in the html file
    assert "&lt;admin&gt;" in html_content
    assert "&lt;b&gt;bad&lt;/b&gt;" in html_content 



    