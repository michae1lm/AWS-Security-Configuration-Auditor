# Official references

Reviewed during implementation on November 18, 2026. The installed/tested SDK is Boto3 1.44.6 with Botocore 1.44.6; the dependency lock is in `requirements.txt`. References specify AWS behavior; `control_catalog.md` specifies this project's chosen baselines.

- [AWS CLI v2 installation](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [AWS CLI Identity Center setup](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [Boto3 credential profiles](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
- [Boto3 paginators](https://docs.aws.amazon.com/boto3/latest/guide/paginators.html)
- [EC2 DescribeSecurityGroups](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_security_groups.html)
- [EC2 DescribeInstances and metadata options](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_instances.html)
- [EC2 DescribeVolumes](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/describe_volumes.html)
- [S3 ListBuckets paginator](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/paginator/ListBuckets.html)
- [S3 GetBucketLocation](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_location.html)
- [S3 bucket public access block](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_public_access_block.html)
- [S3Control effective account public access block](https://docs.aws.amazon.com/boto3/latest/reference/services/s3control/client/get_public_access_block.html)
- [S3 account public access block absence code](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html)
- [S3 bucket versioning](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_versioning.html)
- [IAM ListAccessKeys](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_access_keys.html)
- [IAM GetLoginProfile and NoSuchEntity](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_login_profile.html)
- [IAM ListMFADevices](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/list_mfa_devices.html)
- [GitHub checkout](https://github.com/actions/checkout)
- [GitHub setup-python](https://github.com/actions/setup-python)

The implementation follows the guide's explicit GetBucketLocation fallback for older ListBuckets responses. The AWS reference now recommends HeadBucket for region discovery; future changes should review its required permissions. Current paginated ListBuckets responses can already supply BucketRegion.
