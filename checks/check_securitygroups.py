# ec2.describe_security_groups()

# securitygroup = ec2.describe_security_groups()

securitygroup = {
    "SecurityGroups": [
        {
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": []
                }
            ],
            "Description": "My security group",
            "Tags": [
                {
                    "Value": "SG1",
                    "Key": "Name"
                }
            ],
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [],
                    "UserIdGroupPairs": [
                        {
                            "UserId": "123456789012",
                            "GroupId": "sg-903004f8"
                        }
                    ],
                    "PrefixListIds": []
                },
                {
                    "PrefixListIds": [],
                    "FromPort": 22,
                    "IpRanges": [
                        {
                            "Description": "Access from NY office",
                            "CidrIp": "203.0.113.0/24"
                        }
                    ],
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": []
                    }
            ],
            "GroupName": "MySecurityGroup",
            "VpcId": "vpc-1a2b3c4d",
            "OwnerId": "123456789012",
            "GroupId": "sg-903004f8",
        }
    ]
}

for instance in securitygroup["SecurityGroups"]:
    for IpPermissions in instance["IpPermissions"]:
        print("Here are Ip Permissions")
        if "FromPort" in IpPermissions:
            print(IpPermissions["FromPort"],"FromPort")
        if "ToPort" in IpPermissions:
            print(IpPermissions["ToPort"],"Toport")
        
        for ranges in IpPermissions.get('IpRanges',[]): # .get [] incase IpRanges doesn't exist
            if "CidrIp" in ranges:
                print(ranges['CidrIp'])

           
    