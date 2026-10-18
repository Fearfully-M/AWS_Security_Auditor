from botocore.exceptions import ClientError
from checks.check_s3publicaccess import check_s3publicaccess
import json


class FakeS3Client:
    def __init__(self, buckets):
        self.buckets = buckets

    def list_buckets(self):
        return {"Buckets": [{"Name": bucket_name} for bucket_name in self.buckets]}

    def get_public_access_block(self, Bucket):
        bucket_data = self.buckets[Bucket]

        if "bpa_error" in bucket_data:
            raise ClientError(
                {"Error": {"Code": bucket_data["bpa_error"], "Message": "Error"}},
                "GetPublicAccessBlock",
            )

        elif "bpa_denied" in bucket_data:
            raise ClientError(
                {
                    "Error": {
                        "Code": bucket_data["bpa_denied"],
                        "Message": "Permission Not Granted",
                    }
                },
                "GetPublicAccessBlock",
            )

        return {"PublicAccessBlockConfiguration": bucket_data["bpa"]}

    def get_bucket_policy(self, Bucket):
        bucket_data = self.buckets[Bucket]

        if "policy_error" in bucket_data:
            raise ClientError(
                {
                    "Error": {
                        "Code": bucket_data["policy_error"],
                        "Message": "policy_error",
                    }
                },
                "GetBucketPolicy",
            )

        elif "raw_policy" in bucket_data:
            return {"Policy": bucket_data["raw_policy"]}

        elif "policy" not in bucket_data:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchBucketPolicy",
                        "Message": "The bucket policy does not exist",
                    }
                },
                "GetBucketPolicy",
            )

        return {"Policy": json.dumps(bucket_data["policy"])}


def test_public_bucket_with_bpa_disabled():
    client = FakeS3Client(
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
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket-a/*",
                        }
                    ],
                },
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["threat_type"] == "Publicly Accessible S3 Bucket"

    explanation = findings[0]["explanation"]
    assert "disabled" in explanation


def test_bucket_with_internal_failure():
    client = FakeS3Client(
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
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket-a/*",
                        }
                    ],
                },
            },
            "bucket-b": {
                "bpa_error": "InternalError",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket-b/*",
                        }
                    ],
                },
            },
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 2

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[1]["resource_id"] == "bucket-b"

    assert findings[0]["severity"] == "High"
    assert findings[1]["severity"] == "Unknown"


def test_bucket_with_low_severity():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "policy": {
                    "Version": "2013-12-20",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket-a/*",
                        }
                    ],
                },
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Low"

    explanation = findings[0]["explanation"]
    assert "enabled" in explanation


def test_no_such_bucket_policy():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 0


def test_bucket_policy_access_denied():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "policy_error": "AccessDenied",
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Unknown"
    assert findings[0]["threat_type"] == "Permission Not Granted"


def test_bucket_bad_json():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": False,
                },
                "raw_policy": "{definitely not valid json, bro",
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Unknown"
    assert findings[0]["threat_type"] == "Malformed Policy Document"


def test_access_denied_on_BPA_lookup():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "bpa_denied": "AccessDenied",
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Unknown"
    assert findings[0]["threat_type"] == "Permission Not Granted"


def test_BPA_enabled_no_public_policy():
    client = FakeS3Client(
        {
            "bucket-a": {
                "bpa": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
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

    findings = check_s3publicaccess(client)

    assert len(findings) == 0


def test_BPA_disabled_no_public_policy():
    client = FakeS3Client(
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

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["threat_type"] == "BPA is disabled"


def test_BPA_disabled_deny_policy():
    client = FakeS3Client(
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
                            "Effect": "Deny",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::bucket-a/*",
                        }
                    ],
                },
            }
        }
    )

    findings = check_s3publicaccess(client)

    assert len(findings) == 1

    assert findings[0]["resource_id"] == "bucket-a"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["threat_type"] == "BPA disabled but policy is set to Deny"
