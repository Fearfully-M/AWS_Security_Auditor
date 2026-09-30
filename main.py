import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import sys
import argparse
from checks import check_securitygroups, check_ec2tags, check_iam_mfa, check_s3publicaccess

def main():

    # initialize clients
    ec2 = boto3.client("ec2")
    s3 = boto3.client("s3")
    iam = boto3.client("iam")

    findings = [] # store vulnerabilities
    try:
        sg_findings = check_securitygroups(ec2.describe_security_groups())
    # TODO
        # call functions for security group, tag, IAM/MFA, and s3 security vulnerability findings
        # tag_findings = check_ec2tags(ec2)
        # iam_findings = check_iam_mfa(iam)
        # s3_findings = check_s3publicacess(s3)

    except NoCredentialsError: # if no AWS credentials are found
        print("No AWS credentials are loaded. Please run credentials with 'aws configure'")
        sys.exit()

    except ClientError: # if client doesn't provide appropriate
        print("Permission Error. Read Permissions required to evaluate system vulnerabilities")
        sys.exit()
    
# TODO: implement the following:

    # # concatenate all findings into one dict
    # all_findings = sg_findings + tag_findings + iam_findings + s3_findings

    # # enhance findings with AI generated recommendations
    # augment_findings = add_ai_recommendations(all_findings)

    # # generate findings and save as CSV/HTML
    # generate_security_report(augment_findings)

    
if __name__ == "__main__":
    main()