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