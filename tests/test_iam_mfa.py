from checks import check_iam_mfa

# used for testing
class FakeIAMClient:

    def __init__(self, ):
        ...
        
    def list_users(self):
       ...
  
    def list_attached_user_policies(self,UserName):
        ...
    
    def get_policy(self,PolicyArn):
        ...
    
    def get_policy_version(self, PolicyArn, VersionId):
        ...
    
    def list_mfa_devices(self, UserName):
       ...

# iam_client = FakeIAMClient()
# check_iam_mfa(iam_client)
def test_user_without_mfa_flagged():
    findings = check_iam_mfa(FakeIAMClient())
    assert findings [0]['threat_type'] == 'MFA Not Enabled'
    assert findings[0]['serverity'] in ['Low', 'Medium', 'High', 'Unknown']