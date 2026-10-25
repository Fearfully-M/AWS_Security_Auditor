from botocore.exceptions import ClientError
from datetime import datetime  # used for testing fake data
import json


def check_s3publicaccess(s3_client):
    findings = []
    # initialize list of buckets on the s3 client
    try:
        buckets = s3_client.list_buckets()
    # if it fails due to lack of permissions
    except ClientError as e:
        findings.append(
            {
                "domain": "S3",
                "resource_id": "NA",
                "severity": "NA",
                "threat_type": f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
                "explanation": f"Failed to list S3 Buckets {e.response['Error']['Message']}",
                "recommendation": "",
            }
        )
        return findings

    # determine if bpa is configured or due to lack of permissions
    for bucket in buckets["Buckets"]:
        bpa_enabled = False
        bucket_name = bucket["Name"]
        try:
            bpa = s3_client.get_public_access_block(Bucket=bucket_name)

            # check if Block Public Access is enabled
            config = bpa["PublicAccessBlockConfiguration"]
            bpa_enabled = (
                config["BlockPublicAcls"]
                and config["IgnorePublicAcls"]
                and config["BlockPublicPolicy"]
                and config["RestrictPublicBuckets"]
            )

        except ClientError as e:  # BPA is not configured
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                bpa_enabled = False

            # if it fails due to lack of permissions
            elif e.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    {
                        "domain": "S3",
                        "resource_id": f"{bucket_name}",
                        "severity": "Unknown",
                        "threat_type": "Permission Not Granted",
                        "explanation": f"Access Denied. Permissions are not granted. {e.response['Error']['Message']}",
                        "recommendation": "",
                    }
                )
                continue
            else:  # unexpected errors
                findings.append(
                    {
                        "domain": "S3",
                        "resource_id": f"{bucket_name}",
                        "severity": "Unknown",
                        "threat_type": "Error",
                        "explanation": f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
                        "recommendation": "",
                    }
                )
                continue

        # get the bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        except ClientError as e:  # if no bucket policy
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                if not bpa_enabled:
                    # No bucket policy was found and BPA is disabled
                    severity = "Medium"
                    bpa_status = "disabled"
                    findings.append(
                        {
                            "domain": "S3",
                            "resource_id": bucket_name,
                            "severity": severity,
                            "threat_type": "Block Public Access Disabled",
                            "explanation": f"No bucket policy. Block Public Access is {bpa_status}.",
                            "recommendation": "",
                        }
                    )
                    continue
                # BPA is enabled, no bucket policy found.
                elif bpa_enabled:
                    continue

            elif e.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    {
                        "domain": "S3",
                        "resource_id": f"{bucket_name}",
                        "severity": "Unknown",
                        "threat_type": "Permission Not Granted",
                        "explanation": f"Failed to get policy for bucket: {bucket_name}, {e.response['Error']['Message']}",
                        "recommendation": "",
                    }
                )
                continue
            else:  # unexpected errors
                findings.append(
                    {
                        "domain": "S3",
                        "resource_id": f"{bucket_name}",
                        "severity": "Unknown",
                        "threat_type": "Error",
                        "explanation": f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
                        "recommendation": "",
                    }
                )
                continue

        # have the policy, load it into JSON, if issue then return an unknown
        try:
            policy_json = json.loads(policy["Policy"])
        except json.JSONDecodeError:  # for JSON decoding error
            findings.append(
                {
                    "domain": "S3",
                    "resource_id": bucket_name,
                    "severity": "Unknown",
                    "threat_type": "Malformed Policy Document",
                    "explanation": f"Unable to parse bucket policy JSON for bucket {bucket_name}.",
                    "recommendation": "",
                }
            )
            continue
        # policy can never be unassigned because any unassigned policy goes through the above continue statements
        # and the iteration is skipped.

        statements = policy_json.get("Statement", [])

        # convert all policies to a list so it always can be looped over
        if isinstance(statements, dict):
            statements = [statements]

        # set to false, initially not publicly exposed
        public_allow_found = False

        # check each statement
        for statement in statements:
            if statement.get("Effect") == "Allow":
                principal = statement.get("Principal")

                is_public = principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                )

                # determine truly if the bucket is public with principal/policy and bpa_enabled
                if is_public:
                    public_allow_found = True

        # exposed to public and BPA is not enabled
        if public_allow_found and not bpa_enabled:
            # BPA is disabled but effect is set to 'Deny'
            severity = "High"
            bpa_status = "disabled"
            findings.append(
                {
                    "domain": "S3",
                    "resource_id": bucket_name,
                    "severity": severity,
                    "threat_type": "Publicly Accessible S3 Bucket",
                    "explanation": f"Bucket has a public policy. Block Public Access is {bpa_status}.",
                    "recommendation": "",
                }
            )
        # exposed to public BUT BPA is enabled
        elif public_allow_found and bpa_enabled:
            # BPA is disabled but effect is set to 'Deny'
            severity = "Low"
            bpa_status = "enabled"
            findings.append(
                {
                    "domain": "S3",
                    "resource_id": bucket_name,
                    "severity": severity,
                    "threat_type": "Public Bucket Policy Found",
                    "explanation": f"Bucket has a public policy but Block Public Access is {bpa_status}.",
                    "recommendation": "",
                }
            )
        # not exposed to public but BPA is disabled
        elif not public_allow_found and not bpa_enabled:
            # BPA is disabled but effect is set to 'Deny'
            severity = "Medium"
            bpa_status = "disabled"
            findings.append(
                {
                    "domain": "S3",
                    "resource_id": bucket_name,
                    "severity": severity,
                    "threat_type": "Block Public Access Disabled",
                    "explanation": f"Bucket has a private policy. Block Public Access is {bpa_status}.",
                    "recommendation": "",
                }
            )

    return findings
