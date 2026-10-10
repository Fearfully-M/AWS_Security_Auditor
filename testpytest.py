def test_public_bucket_with_bpa_disabled():
    client = FakeS3Client()
    findings = check_s3publicaccess(client)

    assert len(findings) == 1
    assert findings[0]['severity'] == 'High'
    assert findings[0]['threat_type'] == 'Publicly Accessible S3 Bucket'

    explanation = findings[0]['explanation']
    assert "disabled" in explanation


def test_bucket_with_internal_failure():
    client = FakeS3Client()
    findings = check_s3publicaccess(client)

    assert len(findings) == 2

    assert findings[0]['resource_id'] == 'bucket-a'
    assert findings[1]['resource_id'] == 'bucket-b'

    assert findings[0]['severity'] == 'High'
    assert findings[1]['severity'] == 'Unknown'

