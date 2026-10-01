from checks import check_iam_mfa, FakeIAMClient
def test_user_without_mfa_flagged():
    findings = check_iam_mfa(FakeIAMClient())
    assert findings [0]['threat_type'] == 'MFA Not Enabled'
    assert findings[0]['serverity'] in ['Low', 'Medium', 'High', 'Unknown']