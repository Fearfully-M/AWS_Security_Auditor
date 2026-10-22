from botocore.exceptions import ClientError

def check_securitygroups(ec2_client):
    findings = []  # store vulnerability findings
    try:
        securitygroups = ec2_client.describe_security_groups()
    except ClientError as e:
        findings.append(
            {
                "domain": "SecurityGroup",
                "resource_id": "NA",
                "severity": "NA",
                "threat_type": f"{e.response['Error']['Code']}: {e.response['Error']['Message']}",
                "explanation": "EC2 check failed due to insufficient permissions",
                "recommendation": "",
            }
        )
        return findings

    sensitive_ports = {22, 3306, 5432}  # common sensitive ports

    for securitygroup in securitygroups["SecurityGroups"]:  # check each security group instance
        for IpPermissions in securitygroup["IpPermissions"]:
            source_vulnerability = False  # set vulnerability initally to False
            port_vulnerability = False

            # if a security group is missing a fromPort or toPort
            if "FromPort" not in IpPermissions or "ToPort" not in IpPermissions:
                continue

            if "FromPort" in IpPermissions:  # determine if using a sensitive port
                fromPort = IpPermissions["FromPort"]

            if "ToPort" in IpPermissions:
                toPort = IpPermissions["ToPort"]

            # determine if the fromPort and toPort ranges touch a sensitive port
            for sensitive_port in sensitive_ports:
                if fromPort <= sensitive_port <= toPort:
                    port_vulnerability = True
                    break

            for ranges in IpPermissions.get("IpRanges", []):  # .get(,[]) incase IpRanges doesn't exist
                if "CidrIp" in ranges:
                    if (ranges["CidrIp"] == "0.0.0.0/0"):  # determine if using public source
                        source_vulnerability = True

            # append to dictionary each type of vulnerability
            if source_vulnerability and port_vulnerability:
                findings.append(
                    {
                        "domain": "SecurityGroup",
                        "resource_id": f"{securitygroup['GroupId']} ({securitygroup['GroupName']})",
                        "severity": "High",
                        "threat_type": "Source Vulnerability and Port Vulnerability",
                        "explanation": f"A port is publicy exposed due to CidrIp being set to '0.0.0.0/0'",
                        "recommendation": "",
                    }
                )

    return findings


client = {
    "NextToken": "string",
    "SecurityGroups": [
        {
            "GroupId": "string",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "string",
                    "FromPort": 123,
                    "ToPort": 123,
                    "UserIdGroupPairs": [
                        {
                            "Description": "string",
                            "UserId": "string",
                            "GroupName": "string",
                            "GroupId": "string",
                            "VpcId": "string",
                            "VpcPeeringConnectionId": "string",
                            "PeeringStatus": "string",
                        },
                    ],
                    "IpRanges": [
                        {"Description": "string", "CidrIp": "string"},
                    ],
                    "Ipv6Ranges": [
                        {"Description": "string", "CidrIpv6": "string"},
                    ],
                    "PrefixListIds": [
                        {"Description": "string", "PrefixListId": "string"},
                    ],
                },
            ],
            "Tags": [
                {"Key": "string", "Value": "string"},
            ],
            "VpcId": "string",
            "SecurityGroupArn": "string",
            "OwnerId": "string",
            "GroupName": "string",
            "Description": "string",
            "IpPermissions": [
                {
                    "IpProtocol": "string",
                    "FromPort": 123,
                    "ToPort": 123,
                    "UserIdGroupPairs": [
                        {
                            "Description": "string",
                            "UserId": "string",
                            "GroupName": "string",
                            "GroupId": "string",
                            "VpcId": "string",
                            "VpcPeeringConnectionId": "string",
                            "PeeringStatus": "string",
                        },
                    ],
                    "IpRanges": [
                        {"Description": "string", "CidrIp": "string"},
                    ],
                    "Ipv6Ranges": [
                        {"Description": "string", "CidrIpv6": "string"},
                    ],
                    "PrefixListIds": [
                        {"Description": "string", "PrefixListId": "string"},
                    ],
                },
            ],
        },
    ],
}


# used for testing
class FakeSecurityGroupClient:
    def __init__(self, securitygroups=None, error=None):
        self.securitygroups = securitygroups or []
        self.error = error

    def describe_security_groups(self):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "DescribeSecurityGroups",
            )
        return {"SecurityGroups": self.securitygroups}


client = FakeSecurityGroupClient(
    [
        {
            "GroupId": "sg-123",
            "GroupName": "ssh-public",
            "IpPermissions": [
                {
                    "FromPort": 21,
                    "ToPort": 24,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        },
        {
            "GroupId": "sg-456",
            "GroupName": "https-public",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        },
    ]
)

check_securitygroups(client)
