from tests.test_s3publicaccess import FakeS3Client
from tests.test_iam_mfa import FakeIAMClient
from botocore.exceptions import ClientError
from main import run_audit

# custom FakeEC2Client to handle both ec2 tags and security groups
class FakeEC2Client:
    def __init__(self, instances=None, securitygroups= None, error=None):
        self.instances = instances or []
        self.securitygroups = securitygroups or []
        self.error = error

    def describe_instances(self):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "DescribeInstances",
            )

        return {"Reservations": [{"Instances": self.instances}]}

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

    
def test_run_audit_combines_findings():
    instances =[
            {"InstanceId": "i-good", "Tags": [{"Key": "Name", "Value": "web-server"}]},
            {"InstanceId": "i-bad", "Tags": [{"Key": "Environment", "Value": "prod"}]},
        ]
    
    securitygroups=[
        {
            "GroupId": "sg-123-range",
            "GroupName": "ssh-public",
            "IpPermissions": [
                {
                    "FromPort": 3100,
                    "ToPort": 3401,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        },
    ]

    fake_ec2 = FakeEC2Client(instances=instances,securitygroups=securitygroups)
            

    fake_s3 = FakeS3Client(
            {
                "bucket-a": {
                    "bpa": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": False,
                    },
                    "policy": {
                        "Version": "2013-12-20",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::bucket-a/*",
                            }
                        ],
                    },
                }
            }
        )

    mock_users = [
            {
                "UserName": "john.doe",
            },
        ]
    
    mock_mfa_map = {
            
        }

    mock_policy_versions_map = {
        ("arn:aws:iam::123456789012:policy/CustomS3ReadOnly", "v1"): {
            "PolicyVersion": {
                "Document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:PutObject",
                        ],
                        "Resource": [
                            "arn:aws:s3:::my-bucket/*"
                        ]
                    }
                ]
}
            }
        }
    }
    mock_policy = {
        'arn:aws:iam::123456789012:policy/CustomS3ReadOnly': {
            'Policy': {
                'PolicyName': 'CustomS3ReadOnly',
                'Arn': 'arn:aws:iam::123456789012:policy/CustomS3ReadOnly',
                'DefaultVersionId': 'v1',
            
            }
        }
        }
        
    mock_attached_policies = {
        'john.doe': [
            {
                'PolicyName': 'CustomS3ReadOnly',
                'PolicyArn': 'arn:aws:iam::123456789012:policy/CustomS3ReadOnly'
            }
        ],
    }

    fake_iam = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)

    findings = run_audit(fake_ec2,fake_s3,fake_iam)

    print(findings)

    assert len(findings) == 4

    assert findings[0]['domain'] == 'SecurityGroup'
    assert findings[0]['resource_id'] == 'sg-123-range (ssh-public)'
    assert findings[0]['severity'] == 'High'
    assert findings[0]['threat_type'] == 'Source Vulnerability and Port Vulnerability'

    assert findings[1]['domain'] == 'EC2'
    assert findings[1]['resource_id'] == 'i-bad'
    assert findings[1]['severity'] == 'Low'
    assert findings[1]['threat_type'] == 'Missing EC2 Instance tags'

    assert findings[2]['domain'] == 'IAM/MFA'
    assert findings[2]['resource_id'] == 'john.doe'
    assert findings[2]['severity'] == 'Medium'
    assert findings[2]['threat_type'] == 'MFA Not Enabled'

    assert findings[3]['domain'] == 'S3'
    assert findings[3]['resource_id'] == 'bucket-a'
    assert findings[3]['severity'] == 'Medium'
    assert findings[3]['threat_type'] == 'Block Public Access Disabled'
   
