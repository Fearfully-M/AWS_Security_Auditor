import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import sys
import argparse
from checks.check_securitygroups import check_securitygroups
from checks.check_ec2tags import check_ec2tags
from checks.check_iam_mfa import check_iam_mfa
from checks.check_s3publicaccess import check_s3publicaccess
from report_generator import generate_csv_report, generate_html_report, pretty_CLI_output
from add_ai_recommendations import add_ai_recommendations
import anthropic

def main():

    # add CLI commands
    parser = argparse.ArgumentParser(
        prog="AWS_Security_Auditor",
        description="Scans AWS account for security misconfigurations. Checks for publicly accessible S3 buckets, EC2 instances missing tags, IAM users without MFA, and overly permissive security groups. Generates a detailed CSV or HTML report with findings and recommendations.",
        epilog="python main.py --ai --report html",
    )

    # generating or not generating a report is mutually exclusive, eliminate conflicting options
    group = parser.add_mutually_exclusive_group() 
    group.add_argument("--report", choices =["html", "csv", "both"], default="csv") # allow the user to select report generation format
    group.add_argument("--no-report", action="store_true")
    
    parser.add_argument("--ai", action="store_true") # select for optional ai recommendations

    args = parser.parse_args() # parse users selections

    # if user selects 'no report' don't generate default csv, else generate respective file format
    file_format = None if args.no_report else args.report

    # call functions for security group, tag, IAM/MFA, and s3 security vulnerability findings
    try:
        ec2 = boto3.client("ec2")
        s3 = boto3.client("s3")
        iam = boto3.client("iam")
        all_findings = run_audit(ec2,s3,iam)
    except NoCredentialsError:  # if no AWS credentials are found
        print(
            "No AWS credentials are loaded. Please run credentials with 'aws configure'"
        )
        sys.exit(1)

    except ClientError:  # if client doesn't provide appropriate
        print(
            "Permission Error. Read Permissions required to evaluate system vulnerabilities"
        )
        sys.exit(1)

    
    # # enhance findings with AI generated recommendations
    if args.ai:
        all_findings = add_ai_recommendations(all_findings, ai_client)

    # # generate findings and save as CSV/HTML
    generate_security_report(all_findings,file_format)


# concatenate all findings and return them
def run_audit(ec2_client, s3_client, iam_client):
    sg_findings = check_securitygroups(ec2_client)
    tag_findings = check_ec2tags(ec2_client)
    iam_findings = check_iam_mfa(iam_client)
    s3_findings = check_s3publicaccess(s3_client)

    # concatenate all findings into a list of dicts
    all_findings = sg_findings + tag_findings + iam_findings + s3_findings

    return all_findings

# takes CLI input and determines what file format to generate the report and if to add optional AI recommendations
def generate_security_report(all_findings, file_format):

    # output results in a nice, readable format to screen
    pretty_CLI_output(all_findings)

    # print to file formatting specified by user
    if file_format == 'csv':
        generate_csv_report(all_findings)
    elif file_format == 'html':
        generate_html_report(all_findings)
    elif file_format == 'both':
        generate_csv_report(all_findings)
        generate_html_report(all_findings)

if __name__ == "__main__":
    main()
