import csv
from rich import print
from rich.console import Console
from rich.table import Table
from rich.text import Text
from datetime import datetime as dt
from pathlib import Path
from html import escape


# takes security auditor findings and saves them into a CSV
def generate_csv_report(findings, report_file=None):
    if report_file is None:
        output_dir = Path("reports/")
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = dt.now().strftime(f"SecurityAuditorResults_%Y-%m-%d_%H-%M-%S.csv")

        report_file = output_dir / filename

    # write results to csv file
    with open(report_file, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "domain",
                "resource_id",
                "severity",
                "threat_type",
                "explanation",
                "recommendation",
            ],
        )

        writer.writeheader()
        writer.writerows(findings)


# takes security auditor findings and saves them into an HTML
def generate_html_report(findings, report_file=None):
    if report_file is None:
        output_dir = Path("reports/")
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = dt.now().strftime(f"SecurityAuditorResults_%Y-%m-%d_%H-%M-%S.html")

        report_file = output_dir / filename

    # write the findings to be put later into html
    html_rows = ""
    for finding in findings:
        if finding['severity'] == 'High':
            severity_class = "severity-high"

        elif finding['severity'] == 'Medium':
            severity_class = "severity-medium"

        elif finding['severity'] == 'Low':
            severity_class = "severity-low"

        else:
            severity_class = "severity-unknown"
        html_rows += f"""
            <tbody>
                <td>{escape(str(finding["domain"]))}</td>
                <td>{escape(str(finding["resource_id"]))}</td>
                <td class = "{severity_class}">{escape(str(finding["severity"]))}</td>
                <td>{escape(str(finding["threat_type"]))}</td>
                <td>{escape(str(finding["explanation"]))}</td>
                <td>{escape(str(finding["recommendation"]))}</td>
            </tbody>
        """

    # write the html, stylize, and input earlier findings that were converted to html
    html = f"""
     <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Security Findings Report</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                margin: 40px;
                color: #333;
                background-color: #fdfdfd;
            }}
            h2 {{
                color: #111;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                background: white;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                border-radius: 6px;
                overflow: hidden;
            }}
            th, td {{
                padding: 12px 16px;
                text-align: left;
                border-bottom: 1px solid #eee;
                font-size: 14px;
            }}
            th {{
                background-color: #24292e;
                color: white;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 0.5px;
            }}
            tr:hover{{
                background-color: #f6f8fa;
            }}
            thead:hover {{
                background-color: #f6f8fa;
            }}
            /* Severity Colors */
            .severity-high {{
                color: #d73a49;
                font-weight: bold;
            }}
            .severity-medium {{
                color: #b08800;
                font-weight: bold;
            }}
            .severity-low {{
                color: #0366d6;
            }}
            .severity-unknown {{
                color: #6f42c1;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
    <h2>Security Findings Report</h2>
    <table>
        <thead>
            <th>Domain</th>
            <th>Resource ID</th>
            <th>Severity</th>
            <th>Threat Type</th>
            <th>Explanation</th>
            <th>Recommendation</th>
        </thead>
        {html_rows}
    </table>
    </body>
    </html>
    """

    # write html to a file
    with open(report_file, "w") as file:
        file.write(html)

# function that outputs the results to screen in a much prettier and easier to read way
def pretty_CLI_output(findings):
    console = Console()
    table = Table(title="Security Findings Report", show_lines=True)

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
        table.add_column(header, style="green" if header == "Domain" else "white")

    # rows and change color of 'severity' respective to levels of severity
    for row in findings:
        severity_value = str(row.get("severity", ""))

        if severity_value == "High":
            severity_cell = Text(severity_value, style="bold red")
        elif severity_value == "Medium":
            severity_cell = Text(severity_value, style="yellow")
        elif severity_value == "Low":
            severity_cell = Text(severity_value, style="blue")
        else:
            severity_cell = Text(severity_value, style="purple")

        table.add_row(
            str(row.get("domain", "")),
            str(row.get("resource_id", "")),
            severity_cell,
            str(row.get("threat_type", "")),
            str(row.get("explanation", "")),
            str(row.get("recommendation", "")),
        )

    console.print(table)
