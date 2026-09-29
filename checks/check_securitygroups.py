from botocore.exceptions import ClientError
# securitygroups = {
#     "SecurityGroups": [
#         {
#             "IpPermissionsEgress": [
#                 {
#                     "IpProtocol": "-1",
#                     "IpRanges": [
#                         {
#                             "CidrIp": "0.0.0.0/0"
#                         }
#                     ],
#                     "UserIdGroupPairs": [],
#                     "PrefixListIds": []
#                 }
#             ],
#             "Description": "My security group",
#             "Tags": [
#                 {
#                     "Value": "SG1",
#                     "Key": "Name"
#                 }
#             ],
#             "IpPermissions": [
#                 {
#                     "IpProtocol": "-1",
#                     "IpRanges": [],
#                     "UserIdGroupPairs": [
#                         {
#                             "UserId": "123456789012",
#                             "GroupId": "sg-903004f8"
#                         }
#                     ],
#                     "PrefixListIds": []
#                 },
#                 {
#                     "PrefixListIds": [],
#                     "FromPort": 22,
#                     "IpRanges": [
#                         {
#                             "Description": "Access from NY office",
#                             "CidrIp": "203.0.113.0/24"
#                         }
#                     ],
#                     "ToPort": 22,
#                     "IpProtocol": "tcp",
#                     "UserIdGroupPairs": []
#                     }
#             ],
#             "GroupName": "MySecurityGroup",
#             "VpcId": "vpc-1a2b3c4d",
#             "OwnerId": "123456789012",
#             "GroupId": "sg-903004f8",
#         }
#     ]
# } 

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
                findings.append({'domain': 'SecurityGroup', 'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})", 'severity':'Critical','threat_type':'Source Vulnerability and FromPort Vulnerability','explanation': f"FromPort {IpPermissions['FromPort']} is publicy exposed due to CidrIp being set to '0.0.0.0/0'",'recommendation':''})

            if source_vulnerability and toPort_vulnerability:
                findings.append({'domain': 'SecurityGroup', 'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})",'severity':'Critical','threat_type':'Source Vulnerability and ToPort Vulnerability','explanation': f"ToPort {IpPermissions['ToPort']} is publicy exposed due to CidrIp being set to '0.0.0.0/0'",'recommendation':''})
                
            if fromPort_vulnerability and not source_vulnerability:
                findings.append({'domain': 'SecurityGroup', 'resource_id': f"{securitygroup['GroupId']} ({securitygroup['GroupName']})",'severity':'Low','threat_type':'Unorthodox FromPort Selected','explanation': f"FromPort {IpPermissions['FromPort']} being used is nonstandard.'",'recommendation':''})

    return findings