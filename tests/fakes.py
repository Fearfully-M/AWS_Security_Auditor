# used for testing
class FakeIAMClient:
    def list_users(self):
       return {
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
    'IsTruncated': True,
    'Marker': 'string'
        }
    def list_attached_user_policies(self,UserName):
        return {
            'AttachedPolicies': [
                {
                    'PolicyName': 'list_attached_policyName',
                    'PolicyArn': 'list_attached_policyArn'
                },
            ],
            'IsTruncated': True,
            'Marker': 'string'
            }
    
    def get_policy(self,PolicyArn):
        return{
            'Policy': {
                'PolicyName': 'string',
                'PolicyId': 'string',
                'Arn': 'Arn_getpolicy()',
                'Path': 'string',
                'DefaultVersionId': 'string',
                'AttachmentCount': 123,
                'PermissionsBoundaryUsageCount': 123,
                'IsAttachable': True,
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
    
    def get_policy_version(self, PolicyArn, VersionId):
        return {
            'PolicyVersion': {
                'Document': '%7B%22Statement%22%3A%20%5B%7B%22Action%22%3A%20%22s3%3AGetObject%22%7D%2C%20%7B%22Action%22%3A%20%22s3%3APutObject%22%7D%5D%7D',
                'VersionId': 'versionIdstring',
                'IsDefaultVersion': True,
                'CreateDate': datetime(2015, 1, 1)
            }
        }
    
    def list_mfa_devices(self, UserName):
        return {
        'MFADevices': [],
        # 'MFADevices': [{
        #             'UserName': 'string',
        #             'SerialNumber': 'string',
        #             'EnableDate': datetime(2015, 1, 1)
        #         },],
        'IsTruncated': False,
        'Marker': 'string'
    }

# iam_client = FakeIAMClient()
# check_iam_mfa(iam_client)