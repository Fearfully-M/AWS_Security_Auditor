from botocore.exceptions import ClientError
from datetime import datetime # used for testing fake data

def check_ec2tags(ec2_client):
    findings = []
    #initialize the reservations
    try:
        reservations = ec2_client.describe_instances()

    # if it fails due to lack of EC2 permissions
    except ClientError:
        findings.append({
                        'domain': 'NA',
                        'resource_id': 'NA',
                        'severity': 'NA',
                        'threat_type': 'NA',
                        'explanation': 'EC2 tags check failed due to insufficient permissions',
                        'recommendation': 'NA',
                        })
        return findings

    # check each instance in reservations
    list_of_no_tags = [] # instances that do not have a name tag
    for reservation in reservations['Reservations']:
        for instance in reservation['Instances']:
            if 'Tags' in instance:
                name_tag_found = False
                for tags in instance['Tags']:
                    if tags['Key'] == 'Name':
                        name_tag_found = True
                        break
                # no name tag found - add instanceid to list of instances with no name tag
                if name_tag_found is False:
                    list_of_no_tags.append(instance['InstanceId'])
                elif name_tag_found is True: # user has name tags
                    pass
            else:
                list_of_no_tags.append(instance['InstanceId'])

    # append the findings for each instance that has no name tags
    if list_of_no_tags:
        for instanceid in list_of_no_tags:
            findings.append({
                            'domain': 'EC2',
                            'resource_id': f'{instanceid}',
                            'severity': 'Low',
                            'threat_type': 'Missing EC2 Instance tags.',
                            'explanation': f'Instance {instanceid} has no name tag.',
                            'recommendation': 'NA',
                            })
        return findings 
    
    else: # user has name tags on all instances, return nothing
        return findings


# used for testing
class FakeEC2Client:
    def describe_instances(self):
        return {
    'NextToken': 'string',
    'Reservations': [
        {
            'ReservationId': 'string',
            'OwnerId': 'string',
            'RequesterId': 'string',
            'Groups': [
                {
                    'GroupId': 'string',
                    'GroupName': 'string'
                },
            ],
            'Instances': [
                {
                    'Architecture': 'i386',
                    'BlockDeviceMappings': [
                        {
                            'DeviceName': 'string',
                            'Ebs': {
                                'AttachTime': datetime(2015, 1, 1),
                                'DeleteOnTermination': False,
                                'Status': 'attaching',
                                'VolumeId': 'string',
                                'AssociatedResource': 'string',
                                'VolumeOwnerId': 'string',
                                'Operator': {
                                    'Managed': True,
                                    'Principal': 'string',
                                    'HiddenByDefault': False
                                },
                                'EbsCardIndex': 123
                            }
                        },
                    ],
                    'ClientToken': 'string',
                    'EbsOptimized': True,
                    'EnaSupport': False,
                    'Hypervisor': 'ovm',
                    'IamInstanceProfile': {
                        'Arn': 'string',
                        'Id': 'string'
                    },
                    'InstanceLifecycle': 'spot',
                    'ElasticGpuAssociations': [
                        {
                            'ElasticGpuId': 'string',
                            'ElasticGpuAssociationId': 'string',
                            'ElasticGpuAssociationState': 'string',
                            'ElasticGpuAssociationTime': 'string'
                        },
                    ],
                    'ElasticInferenceAcceleratorAssociations': [
                        {
                            'ElasticInferenceAcceleratorArn': 'string',
                            'ElasticInferenceAcceleratorAssociationId': 'string',
                            'ElasticInferenceAcceleratorAssociationState': 'string',
                            'ElasticInferenceAcceleratorAssociationTime': datetime(2015, 1, 1)
                        },
                    ],
                    'NetworkInterfaces': [
                        {
                            'Association': {
                                'CarrierIp': 'string',
                                'CustomerOwnedIp': 'string',
                                'IpOwnerId': 'string',
                                'PublicDnsName': 'string',
                                'PublicIp': 'string'
                            },
                            'Attachment': {
                                'AttachTime': datetime(2015, 1, 1),
                                'AttachmentId': 'string',
                                'DeleteOnTermination': False,
                                'DeviceIndex': 123,
                                'Status': 'attached',
                                'NetworkCardIndex': 123,
                                'EnaSrdSpecification': {
                                    'EnaSrdEnabled': True,
                                    'EnaSrdUdpSpecification': {
                                        'EnaSrdUdpEnabled': True
                                    }
                                },
                                'EnaQueueCount': 123
                            },
                            'Description': 'string',
                            'Groups': [
                                {
                                    'GroupId': 'string',
                                    'GroupName': 'string'
                                },
                            ],
                            'Ipv6Addresses': [
                                {
                                    'Ipv6Address': 'string',
                                    'IsPrimaryIpv6': True
                                },
                            ],
                            'MacAddress': 'string',
                            'NetworkInterfaceId': 'string',
                            'OwnerId': 'string',
                            'PrivateDnsName': 'string',
                            'PrivateIpAddress': 'string',
                            'PrivateIpAddresses': [
                                {
                                    'Association': {
                                        'CarrierIp': 'string',
                                        'CustomerOwnedIp': 'string',
                                        'IpOwnerId': 'string',
                                        'PublicDnsName': 'string',
                                        'PublicIp': 'string'
                                    },
                                    'Primary': False,
                                    'PrivateDnsName': 'string',
                                    'PrivateIpAddress': 'string'
                                },
                            ],
                            'SourceDestCheck': False,
                            'Status': 'available',
                            'SubnetId': 'string',
                            'VpcId': 'string',
                            'InterfaceType': 'string',
                            'Ipv4Prefixes': [
                                {
                                    'Ipv4Prefix': 'string'
                                },
                            ],
                            'Ipv6Prefixes': [
                                {
                                    'Ipv6Prefix': 'string'
                                },
                            ],
                            'ConnectionTrackingConfiguration': {
                                'TcpEstablishedTimeout': 123,
                                'UdpStreamTimeout': 123,
                                'UdpTimeout': 123
                            },
                            'Operator': {
                                'Managed': True,
                                'Principal': 'string',
                                'HiddenByDefault': False
                            }
                        },
                    ],
                    'OutpostArn': 'string',
                    'RootDeviceName': 'string',
                    'RootDeviceType': 'ebs',
                    'SecurityGroups': [
                        {
                            'GroupId': 'string',
                            'GroupName': 'string'
                        },
                    ],
                    'SourceDestCheck': False,
                    'SpotInstanceRequestId': 'string',
                    'SriovNetSupport': 'string',
                    'StateReason': {
                        'Code': 'string',
                        'Message': 'string'
                    },
                    'Tags': [
                        {
                            'Key': 'Environment',
                            'Value': 'Production'
                        },
                        {
                            'Key': 'Owner',
                            'Value': 'Bob'
                        },
                        {
                            'Key': 'Co-Owner',
                            'Value': 'Lisa'
                        },
                        {
                            'Key': 'Name',
                            'Value': 'Bob'
                        },
                      
                     
                    ],
                    'VirtualizationType': 'hvm',
                    'CpuOptions': {
                        'CoreCount': 123,
                        'ThreadsPerCore': 123,
                        'AmdSevSnp': 'enabled',
                        'NestedVirtualization': 'enabled'
                    },
                    'CapacityBlockId': 'string',
                    'CapacityReservationId': 'string',
                    'CapacityReservationSpecification': {
                        'CapacityReservationPreference': 'capacity-reservations-only',
                        'CapacityReservationTarget': {
                            'CapacityReservationId': 'string',
                            'CapacityReservationResourceGroupArn': 'string'
                        }
                    },
                    'HibernationOptions': {
                        'Configured': False
                    },
                    'Licenses': [
                        {
                            'LicenseConfigurationArn': 'string'
                        },
                    ],
                    'MetadataOptions': {
                        'State': 'pending',
                        'HttpTokens': 'required',
                        'HttpPutResponseHopLimit': 123,
                        'HttpEndpoint': 'enabled',
                        'HttpProtocolIpv6': 'enabled',
                        'InstanceMetadataTags': 'enabled'
                    },
                    'EnclaveOptions': {
                        'Enabled': True
                    },
                    'BootMode': 'uefi',
                    'PlatformDetails': 'string',
                    'UsageOperation': 'string',
                    'UsageOperationUpdateTime': datetime(2015, 1, 1),
                    'PrivateDnsNameOptions': {
                        'HostnameType': 'resource-name',
                        'EnableResourceNameDnsARecord': True,
                        'EnableResourceNameDnsAAAARecord': False
                    },
                    'Ipv6Address': 'string',
                    'TpmSupport': 'string',
                    'MaintenanceOptions': {
                        'AutoRecovery': 'default',
                        'RebootMigration': 'default'
                    },
                    'CurrentInstanceBootMode': 'uefi',
                    'NetworkPerformanceOptions': {
                        'BandwidthWeighting': 'ebs-1'
                    },
                    'Operator': {
                        'Managed': False,
                        'Principal': 'string',
                        'HiddenByDefault': True
                    },
                    'SecondaryInterfaces': [
                        {
                            'Attachment': {
                                'AttachTime': datetime(2015, 1, 1),
                                'AttachmentId': 'string',
                                'DeleteOnTermination': False,
                                'DeviceIndex': 123,
                                'Status': 'attaching',
                                'NetworkCardIndex': 123
                            },
                            'MacAddress': 'string',
                            'SecondaryInterfaceId': 'string',
                            'OwnerId': 'string',
                            'PrivateIpAddresses': [
                                {
                                    'PrivateIpAddress': 'string'
                                },
                            ],
                            'SourceDestCheck': True,
                            'Status': 'in-use',
                            'SecondarySubnetId': 'string',
                            'SecondaryNetworkId': 'string',
                            'InterfaceType': 'secondary'
                        },
                    ],
                    'InstanceId': 'string',
                    'ImageId': 'string',
                    'State': {
                        'Code': 123,
                        'Name': 'running'
                    },
                    'PrivateDnsName': 'string',
                    'PublicDnsName': 'string',
                    'StateTransitionReason': 'string',
                    'KeyName': 'string',
                    'AmiLaunchIndex': 123,
                    'ProductCodes': [
                        {
                            'ProductCodeId': 'string',
                            'ProductCodeType': 'devpay'
                        },
                    ],
                    'InstanceType': 'a1.large',
                    'LaunchTime': datetime(2015, 1, 1),
                    'Placement': {
                        'AvailabilityZoneId': 'string',
                        'Affinity': 'string',
                        'GroupName': 'string',
                        'PartitionNumber': 123,
                        'HostId': 'string',
                        'Tenancy': 'host',
                        'SpreadDomain': 'string',
                        'HostResourceGroupArn': 'string',
                        'GroupId': 'string',
                        'AvailabilityZone': 'string'
                    },
                    'KernelId': 'string',
                    'RamdiskId': 'string',
                    'Platform': 'Windows',
                    'Monitoring': {
                        'State': 'enabled'
                    },
                    'SubnetId': 'string',
                    'VpcId': 'string',
                    'PrivateIpAddress': 'string',
                    'PublicIpAddress': 'string'
                },
            ]
        },
    ]
}

        
ec2_client = FakeEC2Client()
check_ec2tags(ec2_client)