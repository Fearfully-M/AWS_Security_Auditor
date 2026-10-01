from botocore.exceptions import ClientError
from datetime import datetime # used for testing fake data
from urllib.parse import unquote
import json

# checks if user is using MFA
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
            severity, unknown_action_list = get_user_severity(iam_client, username)
            joined_unknown_actions = ', '.join(unknown_action_list)
            if not unknown_action_list: # if no unknowns in list
                findings.append({
                                'domain': 'IAM/MFA',
                                'resource_id': username,
                                'severity': f'{severity}',
                                'threat_type': 'MFA Not Enabled',
                                'explanation': f'IAM user {username} does not have an MFA device configured.',
                                'recommendation': 'Enable MFA for this IAM User',
                            })
            else: # if there are unknowns in the list
                findings.append({
                            'domain': 'IAM/MFA',
                            'resource_id': username,
                            'severity': f'{severity}',
                            'threat_type': 'MFA Not Enabled',
                            'explanation': f'IAM user {username} does not have an MFA device configured. The following unknown actions were found: {joined_unknown_actions}.',
                            'recommendation': 'Enable MFA for this IAM User',
                        })
    return findings

# function that determines the severity of not having MFA based on IAM user privileges
def get_user_severity(iam_client, username):

    # get list of user policies
    user_policy = iam_client.list_attached_user_policies(UserName=username)

    # start of a list of severity level of all policies
    severity_list = []
    unknown_actions_list = []

    # find arn in user policy
    for policy in user_policy['AttachedPolicies']:
        if 'PolicyArn' in policy:
            policyarn = policy['PolicyArn']

        # get calls - needed to get to the encoded doc
        policy_meta = iam_client.get_policy(PolicyArn=policyarn)
        version_id = policy_meta['Policy']['DefaultVersionId']
        version = iam_client.get_policy_version(PolicyArn=policyarn, VersionId=version_id)

        # get encoded doc, decode and then load into JSON
        encoded_doc = version['PolicyVersion']['Document']
        decoded_doc = unquote(encoded_doc)
        policy_json = json.loads(decoded_doc)

        # homogenize each action string into a list, if already a list keep as is
        for statement in policy_json['Statement']:
            if isinstance(statement['Action'], str):
                actions = [statement['Action']]
            else:
                actions = statement['Action']

            # append the severity of the IAM statement action to the list  
            severity, unknown_action = get_action_tier(actions) 
            if isinstance(severity, int): # if severity not unknown append to list
                severity_list.append(severity)
            else:
                unknown_actions_list.extend(unknown_action)

 # if any unknown statements then return with Unknown severity and the list of unknown actions
    if unknown_actions_list:
         # any unknown action forces Unknown severity overall, even if severity_list
         # has values too and if severity_list is ever empty, this branch is
         # guaranteed to have caught it already (every action lands in one list or the other)
         return 'Unknown', unknown_actions_list
    
    # determine highest severity
    highest_severity = max(severity_list) # get the highest severity 
 
    # convert to string and return the severity level
    return ['Low', 'Medium', 'High'][highest_severity - 1], unknown_actions_list

# determines severity of action statement based on verb type
def get_action_tier(actions):

    read_verbs = ('Get', 'List', 'Describe')
    mutate_verbs = ('Put', 'Delete', 'Create', 'Terminate', 'Modify', 'Attach', 'Update')
    privilege_escalation = 'iam'

    action_severity = [] # determine max severity action in the list
    unknown_actions = [] # collects unknown verbs that are not accounted for

    # read through each 'Action' in the IAM JSON Policy
    for action in actions:  
        action_verb = action.split(':')[1] # split by ':' and return only the action
        service = action.split(':')[0] # check the type of service
        if action_verb.startswith(read_verbs):
            severity = 1
        elif action_verb.startswith(mutate_verbs):
            severity = 2
        elif service.startswith(privilege_escalation):
            severity = 3
        else:
            unknown_actions.append(action) # if unknown action, collect it here
            continue # do not append a severity value for the unknown action

        # append the severity of the action to the list
        action_severity.append(severity)

    # if any actions are unknown then the severity is unknown
    if unknown_actions:
        severity = 'Unknown'
    else:
        severity = max(action_severity)

    return severity, unknown_actions

# used for testing
# class FakeIAMClient:
#     def list_users(self):
#        return {
#     'Users': [
#         {
#             'Path': 'string',
#             'UserName': 'string',
#             'UserId': 'string',
#             'Arn': 'string',
#             'CreateDate': datetime(2015, 1, 1),
#             'PasswordLastUsed': datetime(2015, 1, 1),
#             'PermissionsBoundary': {
#                 'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
#                 'PermissionsBoundaryArn': 'string'
#             },
#             'Tags': [
#                 {
#                     'Key': 'string',
#                     'Value': 'string'
#                 },
#             ]
#         },
#     ],
#     'IsTruncated': True,
#     'Marker': 'string'
#         }
#     def list_attached_user_policies(self,UserName):
#         return {
#             'AttachedPolicies': [
#                 {
#                     'PolicyName': 'list_attached_policyName',
#                     'PolicyArn': 'list_attached_policyArn'
#                 },
#             ],
#             'IsTruncated': True,
#             'Marker': 'string'
#             }
    
#     def get_policy(self,PolicyArn):
#         return{
#             'Policy': {
#                 'PolicyName': 'string',
#                 'PolicyId': 'string',
#                 'Arn': 'Arn_getpolicy()',
#                 'Path': 'string',
#                 'DefaultVersionId': 'string',
#                 'AttachmentCount': 123,
#                 'PermissionsBoundaryUsageCount': 123,
#                 'IsAttachable': True,
#                 'Description': 'string',
#                 'CreateDate': datetime(2015, 1, 1),
#                 'UpdateDate': datetime(2015, 1, 1),
#                 'Tags': [
#                     {
#                         'Key': 'string',
#                         'Value': 'string'
#                     },
#                         ]
#                     }   
#             }
    
#     def get_policy_version(self, PolicyArn, VersionId):
#         return {
#             'PolicyVersion': {
#                 'Document': '%7B%22Statement%22%3A%20%5B%7B%22Action%22%3A%20%22s3%3AGetObject%22%7D%2C%20%7B%22Action%22%3A%20%22s3%3APutObject%22%7D%5D%7D',
#                 'VersionId': 'versionIdstring',
#                 'IsDefaultVersion': True,
#                 'CreateDate': datetime(2015, 1, 1)
#             }
#         }
    
#     def list_mfa_devices(self, UserName):
#         return {
#         'MFADevices': [],
#         # 'MFADevices': [{
#         #             'UserName': 'string',
#         #             'SerialNumber': 'string',
#         #             'EnableDate': datetime(2015, 1, 1)
#         #         },],
#         'IsTruncated': False,
#         'Marker': 'string'
#     }

# iam_client = FakeIAMClient()
# check_iam_mfa(iam_client)