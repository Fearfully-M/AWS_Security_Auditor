from botocore.exceptions import ClientError
from datetime import datetime  # used for testing fake data


def check_ec2tags(ec2_client):
    findings = []
    # initialize the reservations
    try:
        reservations = ec2_client.describe_instances()

    # if it fails due to lack of EC2 permissions
    except ClientError:
        findings.append(
            {
                "domain": "EC2",
                "resource_id": "NA",
                "severity": "NA",
                "threat_type": "NA",
                "explanation": "EC2 tags check failed due to insufficient permissions",
                "recommendation": "NA",
            }
        )
        return findings

    # check each instance in reservations
    list_of_no_tags = []  # instances that do not have a name tag
    for reservation in reservations["Reservations"]:
        for instance in reservation["Instances"]:
            if "Tags" in instance:
                name_tag_found = False
                for tags in instance["Tags"]:
                    if tags["Key"] == "Name":
                        name_tag_found = True
                        break
                # no name tag found - add instanceid to list of instances with no name tag
                if name_tag_found is False:
                    list_of_no_tags.append(instance["InstanceId"])
                elif name_tag_found is True:  # user has name tags
                    pass
            else:
                list_of_no_tags.append(instance["InstanceId"])

    # append the findings for each instance that has no name tags
    if list_of_no_tags:
        for instanceid in list_of_no_tags:
            findings.append(
                {
                    "domain": "EC2",
                    "resource_id": f"{instanceid}",
                    "severity": "Low",
                    "threat_type": "Missing EC2 Instance tags",
                    "explanation": f"Instance {instanceid} has no name tag.",
                    "recommendation": "NA",
                }
            )
        return findings

    else:  # user has name tags on all instances, return nothing
        return findings
