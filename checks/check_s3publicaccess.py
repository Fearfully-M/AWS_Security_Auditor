from botocore.exceptions import ClientError
from datetime import datetime # used for testing fake data
import json

def check_s3publicaccess(s3_client):
    findings = []
    # initialize list of buckets on the s3 client
    try:
        buckets = s3_client.list_buckets()

    # if it fails due to lack of permissions
    except ClientError:
        findings.append({
            'domain': 'NA',
            'resource_id': 'NA',
            'severity': 'NA',
            'threat_type': 'NA',
            'explanation': 'S3 check failed due to insufficient permissions',
            'recommendation': 'NA',
        })
        return findings
    
    # get the bpa policy
    for bucket in buckets['bucketid']:
        bpa = s3_client.get_public_access_block(bucket['BucketName'])
        get_public_access_block(bucket['name'])
        get_bucket_policy(bucket['name'])

        # parse policy JSON
        # check for principal:'*' with Allow effect
        # if found:

        config = bpa['PublicAccessBlockConfiguration']
        # check if Block Public Access is enabled
        bpa_enabled = (config['BlockPublicAcls'] and
                       config['IgnorePublicAcls'] and
                       config['BlockPublicPolicy'] and 
                        config['RestrictPublicBuckets'])

    
     
    # else:
    #     findings.append({
    #         'domain': 'NA',
    #         'resource_id': 'NA',
    #         'severity': 'High',
    #         'threat_type': 'NA',
    #         'explanation': 'S3 check failed due to insufficient permissions',
    #         'recommendation': 'NA',
    #     })

    #     return findings


    
def get_bucket_policy(s3_client):
    findings = []
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            # no policy exists - no security issue, skip this bucket
            pass # or continue to the next bucket
        else: # if it fails due to lack of permissions
            findings.append({
                'domain': 'S3',
                'resource_id': 'NA',
                'severity': 'NA',
                'threat_type': 'NA',
                'explanation': 'S3 check failed due to insufficient permissions',
                'recommendation': 'NA',
            })
        return findings
    
def get_public_access_block(s3_client):
    findings = []
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # no BPA configured
            pass # or continue to the next bucket
        else: # if it fails due to lack of permissions
            findings.append({
                'domain': 'S3',
                'resource_id': 'NA',
                'severity': 'High',
                'threat_type': 'Block Public Access not configured.',
                'explanation': 'Block Public Access is not configured. Please configure AWS Block Public Access.',
                'recommendation': 'NA',
            })
        return findings
        

class FakeS3Client:
    def list_buckets(self):
       return {
            'Buckets': [
            {
            'Name': 'string',
            'CreationDate': datetime(2015, 1, 1),
            'BucketRegion': 'string',
            'BucketArn': 'string'
            },
        ],
        'Owner': {
            'DisplayName': 'string',
            'ID': 'string'
        },
        'ContinuationToken': 'string',
        'Prefix': 'string'
        }
        

    def get_bucket_policy(self, bucket):
        return {
            'Policy': 'string'
            }

    def get_public_access_block(self, bucket):
        return {
            'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True|False,
            'IgnorePublicAcls': True|False,
            'BlockPublicPolicy': True|False,
            'RestrictPublicBuckets': True|False
            }
        }


s3_client = FakeS3Client()
check_s3publicaccess(s3_client)