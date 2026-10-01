from botocore.exceptions import ClientError

def check_securitygroups(ec2_client):
    findings = [] # store vulnerability findings
    try:
        securitygroups = ec2_client.describe_security_groups()
    except ClientError:
        findings.append({
            'domain': 'NA',
            'resource_id': 'NA',
            'severity': 'NA',
            'threat_type': 'NA',
            'explanation': 'EC2 check failed due to insufficient permissions',
            'recommendation': 'NA',
        })
        return findings

    database_ports = {22, 3306, 5432} # common database ports
    public_ports = {80,443} # common acceptable public ports

    for securitygroup in securitygroups["SecurityGroups"]: # check each security group instance
        for IpPermissions in securitygroup["IpPermissions"]:
            source_vulnerability = False # set vulnerability initally to False
            fromPort_vulnerability = False
            toPort_vulnerability = False

            if "FromPort" in IpPermissions: # determine if using a sensitive port
                if IpPermissions['FromPort'] not in public_ports:
                    fromPort_vulnerability = True
            if "ToPort" in IpPermissions:
                if IpPermissions['ToPort'] in database_ports:
                    toPort_vulnerability = True
            for ranges in IpPermissions.get('IpRanges',[]): #.get(,[]) incase IpRanges doesn't exist
                if "CidrIp" in ranges:
                    if ranges['CidrIp'] == '0.0.0.0/0': # determine if using public source
                        source_vulnerability = True

            # append to dictionary each type of vulnerability
            if source_vulnerability and fromPort_vulnerability:
                findings.append({'domain': 'SecurityGroup',
                                'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})", 
                                'severity':'Critical',
                                'threat_type':'Source Vulnerability and FromPort Vulnerability',
                                'explanation': f"FromPort {IpPermissions['FromPort']} is publicy exposed due to CidrIp being set to '0.0.0.0/0'",
                                'recommendation':''})

            if source_vulnerability and toPort_vulnerability:
                findings.append({'domain': 'SecurityGroup',
                                'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})",
                                'severity':'Critical',
                                'threat_type':'Source Vulnerability and ToPort Vulnerability',
                                'explanation': f"ToPort {IpPermissions['ToPort']} is publicy exposed due to CidrIp being set to '0.0.0.0/0'",
                                'recommendation':''})
                
            if fromPort_vulnerability and not source_vulnerability:
                findings.append({'domain': 'SecurityGroup',
                                'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})",
                                'severity':'Low',
                                'threat_type':'Unorthodox FromPort Selected',
                                'explanation': f"FromPort {IpPermissions['FromPort']} being used is nonstandard.'",
                                'recommendation':''})

    return findings