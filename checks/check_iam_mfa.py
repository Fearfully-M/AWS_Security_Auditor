from botocore.exceptions import ClientError
from datetime import datetime
from urllib.parse import unquote
import json

list_users= {
    'Users': [
        {
            'Path': 'string',
            'UserName': 'string',
            'UserId': 'string',
            'Arn': 'string',
            'CreateDate': datetime(2015, 1, 1),
            'PasswordLastUsed': datetime(2015, 1, 1),
            'PermissionsBoundary': {
                'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
                'PermissionsBoundaryArn': 'string'
            },
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ]
        },
    ],
    'IsTruncated': True|False,
    'Marker': 'string'
}

list_mfa_devices = {
    'MFADevices': [
        {
            'UserName': 'string',
            'SerialNumber': 'string',
            'EnableDate': datetime(2015, 1, 1)
        },
    ],
    'IsTruncated': True|False,
    'Marker': 'string'
}

policy_json = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::some-bucket/*"
    }
  ]
}

get_policy = {
    'Policy': {
        'PolicyName': 'string',
        'PolicyId': 'string',
        'Arn': 'string',
        'Path': 'string',
        'DefaultVersionId': 'string',
        'AttachmentCount': 123,
        'PermissionsBoundaryUsageCount': 123,
        'IsAttachable': True|False,
        'Description': 'string',
        'CreateDate': datetime(2015, 1, 1),
        'UpdateDate': datetime(2015, 1, 1),
        'Tags': [
            {
                'Key': 'string',
                'Value': 'string'
            },
        ]
    }
}

class FakeIAMClient:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                # ... your test data here, same shape as before
            ]
        }


    
def get_user_severity(iam_client, username):

    user_policy = iam_client.list_attached_user_policies(UserName=username)

    for policy in user_policy['AttachedPolicies']:
        if 'PolicyArn' in policy:
            policyarn = policy['PolicyArn']

        policy_meta = iam_client.get_policy(PolicyArn=policyarn)
        version_id = policy_meta['Policy']['DefaultVersionId']
        version = iam_client.get_policy_version(PolicyArn=policyarn, VersionId=version_id)

        encoded_doc = version['PolicyVersion']['Document']
        decoded_doc = unquote(encoded_doc)
        policy_json = json.loads(decoded_doc)

        for statement in policy_json['Statement']: # homogenize into lists since AWS action takes list and str
            if isinstance(statement['Action'], str):
                actions = [statement['Action']]
            else:
                actions = statement['Action']



def check_iam_mfa(iam_client):
    findings = []
    # initialize list of users on iam client
    try: 
        users = iam_client.list_users()
    # if it fails due to lack of IAM permissions
    except ClientError: 
        findings.append({
                'domain': 'NA',
                'resource_id': 'NA',
                'severity': 'NA',
                'threat_type': 'NA',
                'explanation': 'IAM check failed due to insufficient permissions',
                'recommendation': 'NA',
            })
        return findings

    # check each user instance
    for user in users["Users"]:
        username = user['UserName']

        # list of mfa devices on this client
        mfa_devices = iam_client.list_mfa_devices(UserName=username)

        # if it returns an empty list it evaluates to true so no MFA enabled - append to list
        if not mfa_devices['MFADevices']:
            get_user_severity(iam_client, username)
            findings.append({
                        'domain': 'IAM/MFA',
                        'resource_id': username,
                        'severity': 'High',
                        'threat_type': 'MFA Not Enabled',
                        'explanation': f'IAM user {username} does not have an MFA device configured.',
                        'recommendation': 'Enable MFA for this IAM User',
                    })

    return findings