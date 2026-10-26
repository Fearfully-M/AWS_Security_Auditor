from checks.check_iam_mfa import check_iam_mfa
from botocore.exceptions import ClientError
import json

class FakeIAMClient:
    def __init__(
        self,
        users=None,
        mfa_devices_map=None,
        attached_policies=None,
        policies=None,
        policy_versions=None,
        error=None,
    ):
        self.users = users or []
        self.mfa_devices_map = mfa_devices_map or {}
        self.attached_policies = attached_policies or {}
        self.policies = policies or {}
        self.policy_versions = policy_versions or {}
        self.error = error

    def list_users(self):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "ListUsers",
            )
        return {"Users": self.users}

    def list_mfa_devices(self, UserName):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "ListMFADevices",
            )
        devices = self.mfa_devices_map.get(UserName, [])
        return {"MFADevices": devices}

    def list_attached_user_policies(self, UserName):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "ListAttachedUserPolicies",
            )
        attached_policies = self.attached_policies.get(UserName, [])
        return {"AttachedPolicies": attached_policies}

    def get_policy(self, PolicyArn):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "GetPolicy",
            )
        policy_arn = self.policies.get(PolicyArn, {"Policy": {}})
        return policy_arn

    def get_policy_version(self, PolicyArn, VersionId):
        if self.error:
            raise ClientError(
                {
                    "Error": {
                        "Code": self.error,
                        "Message": "Permission Not Granted",
                    }
                },
                "GetPolicyVersion",
            )

        policy_version = self.policy_versions.get((PolicyArn, VersionId), {"PolicyVersion": {}})
        return {
        "PolicyVersion": {
            "Document": json.dumps(policy_version['PolicyVersion']['Document'])
        }
        }

def test_one_user_with_mfa_no_findings():
    mock_users = [
        {
            "UserName": "john.doe",
        },
    ]

    mock_mfa_map = {
        "john.doe": [
            {
                "UserName": "john.doe",
            }
        ],
    }

    client = FakeIAMClient(users=mock_users, mfa_devices_map=mock_mfa_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 0


def test_one_user_no_mfa_read_only_low_finding():
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
                            "s3:ListBucket"
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

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)

    findings = check_iam_mfa(client)

    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'Low'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'

def test_read_and_mutate_action_medium_finding():
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

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'Medium'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'

def test_read_and_mutate_action_privilege_escalation_high_finding():
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
                            "s3:DeleteBucket",
                            "iam:PutUserPolicy",
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

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'High'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'


def test_read_mutate_action_privilege_escalation__unknown_finding():
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
                            "s3:DescribeObject",
                            "s3:TerminateBucket",
                            "s3:FixObject",
                            "iam:PutUserPolicy",
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

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'Unknown'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'

def test_multiple_users_one_medium_one_high_finding():
    mock_users = [
        {
            "UserName": "john.doe",
        },
        {
            "UserName": "sarah.connor",
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
                            "s3:DescribeObject",
                            "iam:PutUserPolicy",
                        ],
                        "Resource": [
                            "arn:aws:s3:::my-bucket/*"
                        ]
                    }
                ]}
            }
        },
    ("arn:aws:iam::aws:policy/ReadOnlyAccess", "v2"): {
                "PolicyVersion": {
                    "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:GetObject",
                                "s3:ListBucket",
                            ],
                            "Resource": [
                                "arn:aws:s3:::my-bucket/*"
                            ]
                        }
                    ]}
                }
            },
        }
    mock_policy = {
        'arn:aws:iam::123456789012:policy/CustomS3ReadOnly': {
            'Policy': {
                'PolicyName': 'CustomS3ReadOnly',
                'Arn': 'arn:aws:iam::123456789012:policy/CustomS3ReadOnly',
                'DefaultVersionId': 'v1',
            
            }
        },
        'arn:aws:iam::aws:policy/ReadOnlyAccess': {
                    'Policy': {
                        'PolicyName': 'CustomS3ReadOnly',
                        'Arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess',
                        'DefaultVersionId': 'v2',
                    
                    }
                },
        }
    
    mock_attached_policies = {
        'john.doe': [
            {
                'PolicyName': 'CustomS3ReadOnly',
                'PolicyArn': 'arn:aws:iam::123456789012:policy/CustomS3ReadOnly'
            }
        ],
         'sarah.connor': [
        {
            'PolicyName': 'ReadOnlyAccess',
            'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        }
    ]
    }

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 2
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'High'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'

    assert findings[1]['resource_id'] == 'sarah.connor'
    assert findings[1]['severity'] == 'Low'
    assert findings[1]['threat_type'] == 'MFA Not Enabled'

def test_mfa_disabled_no_attached_policies_one_finding():
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
                            "s3:DeleteBucket",
                            "iam:PutUserPolicy",
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
        ],
    }

    client = FakeIAMClient(users=mock_users,mfa_devices_map=mock_mfa_map,attached_policies=mock_attached_policies,policies=mock_policy, policy_versions=mock_policy_versions_map)
    findings = check_iam_mfa(client)

    assert len(findings) == 1
    assert findings[0]['resource_id'] == 'john.doe'
    assert findings[0]['severity'] == 'Unknown'
    assert findings[0]['threat_type'] == 'MFA Not Enabled'