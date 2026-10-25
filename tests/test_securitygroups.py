from botocore.exceptions import ClientError
from checks.check_securitygroups import check_securitygroups

class FakeSecurityGroupClient:
    def __init__(self, securitygroups=None, error=None):
        self.securitygroups = securitygroups or []
        self.error = error

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


def test_public_ssh_rule_returns_one_finding():
    client = FakeSecurityGroupClient(
        [
            {
                "GroupId": "sg-123",
                "GroupName": "ssh-public",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
        ]
    )

    findings = check_securitygroups(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "sg-123 (ssh-public)"
    assert findings[0]["severity"] == "High"
    assert findings[0]["threat_type"] == "Source Vulnerability and Port Vulnerability"


def test_public_source_with_port_range_returns_one_finding():
    client = FakeSecurityGroupClient(
        [
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
    )

    findings = check_securitygroups(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "sg-123-range (ssh-public)"
    assert findings[0]["severity"] == "High"
    assert findings[0]["threat_type"] == "Source Vulnerability and Port Vulnerability"


def test_public_source_with_no_sensitive_ports_zero_findings():
    client = FakeSecurityGroupClient(
        [
            {
                "GroupId": "sg-123-zero-findings",
                "GroupName": "ssh-public",
                "IpPermissions": [
                    {
                        "FromPort": 400,
                        "ToPort": 430,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
        ]
    )

    findings = check_securitygroups(client)

    assert len(findings) == 0


def test_private_source_with_sensitive_ports_zero_findings():
    client = FakeSecurityGroupClient(
        [
            {
                "GroupId": "sg-123-zero-findings",
                "GroupName": "ssh-private",
                "IpPermissions": [
                    {
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ],
            },
        ]
    )

    findings = check_securitygroups(client)

    assert len(findings) == 0


def test_no_fromport_no_toport_with_additional_permissions_different_groups_one_finding():
    client = FakeSecurityGroupClient(
        [
            {
                "GroupId": "sg-123-zero-ports",
                "GroupName": "ssh-private",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ],
            },
            {
                "GroupId": "sg-123-sensitive",
                "GroupName": "ssh-public",
                "IpPermissions": [
                    {
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
        ]
    )

    findings = check_securitygroups(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "sg-123-sensitive (ssh-public)"
    assert findings[0]["severity"] == "High"
    assert findings[0]["threat_type"] == "Source Vulnerability and Port Vulnerability"

def test_no_fromport_no_toport_with_additional_permissions_same_group_one_finding():
    client = FakeSecurityGroupClient(
        [
            {
                "GroupId": "sg-123-zero-ports",
                "GroupName": "ssh-private",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ],
            },
            {
                "GroupId": "sg-123-sensitive",
                "GroupName": "ssh-private",
                "IpPermissions": [
                    {
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
        ]
    )

    findings = check_securitygroups(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "sg-123-sensitive (ssh-private)"
    assert findings[0]["severity"] == "High"
    assert findings[0]["threat_type"] == "Source Vulnerability and Port Vulnerability"