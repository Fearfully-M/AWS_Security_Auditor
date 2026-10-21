from botocore.exceptions import ClientError
from checks.check_ec2tags import check_ec2tags


class FakeEC2Client:
    def __init__(self, instances=None, error=None):
        self.instances = instances or []
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


def test_multiple_instances_only_missing_name_tag_is_flagged():
    client = FakeEC2Client(
        [
            {"InstanceId": "i-good", "Tags": [{"Key": "Name", "Value": "web-server"}]},
            {"InstanceId": "i-bad", "Tags": [{"Key": "Environment", "Value": "prod"}]},
        ]
    )

    findings = check_ec2tags(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "i-bad"
    assert findings[0]["severity"] == "Low"
    assert findings[0]["threat_type"] == "Missing EC2 Instance tags"


def test_no_instance_tags():
    findings = FakeEC2Client(
        [
            {"InstanceId": "no-tags", "Tags": ""},
        ]
    )

    findings = check_ec2tags(findings)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "no-tags"
    assert findings[0]["severity"] == "Low"
    assert findings[0]["threat_type"] == "Missing EC2 Instance tags"


def test_no_instance_tags_key():

    findings = FakeEC2Client(
        [
            {"InstanceId": "no-tags-key", "Tags": []},
        ]
    )

    findings = check_ec2tags(findings)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "no-tags-key"
    assert findings[0]["severity"] == "Low"
    assert findings[0]["threat_type"] == "Missing EC2 Instance tags"


def test_no_permission_granted():
    client = FakeEC2Client(
        error="AccessDenied"
    )

    findings = check_ec2tags(client)

    assert len(findings) == 1
    assert findings[0]["resource_id"] == "NA"
    assert findings[0]["severity"] == "NA"
    assert findings[0]["threat_type"] == "NA"
    assert findings[0]['explanation'] == 'EC2 tags check failed due to insufficient permissions'

def test_all_tests_have_name_tags():
    client = FakeEC2Client(
            [
                {"InstanceId": "i-good", "Tags": [{"Key": "Name", "Value": "web-server"}]},
                {"InstanceId": "i-good-1", "Tags": [{"Key": "Name", "Value": "web-server-1"}]},
                {"InstanceId": "i-good-2", "Tags": [{"Key": "Name", "Value": "production-server"}]},
            ]
        )

    findings = check_ec2tags(client)

    assert len(findings) == 0
   