# pcdc-aws-client
Aws client package
AWS client to communicate with S3, SES, iam, sts, ec2, and logs.
to install aws client:
pip install git+http://github.com/chicagopcdc/pcdc-aws-client.git@pcdc_dev#egg=pcdc_aws_client

from pcdc_aws_client.boto import BotoManager

## Run tests:
activate poetry virtual enviorment

Create .env file with the following:

'''
AWS_ACCESS_KEY=[access key for testing account in aws]
AWS_SECRET_ACCESS_KEY=[secret for access key for testing account in aws]
REGION_NAME=[region name]
BUCKET=[test bucket name - * needs to be created via aws console * ]
GROUP_1=[user group for testing * needs to be created via aws console * ]
GROUP_2=[ user group for testing - this group will be created in the tests ]
USER=[ username for existing account associaged with the AWS_ACCESS_KEY above ]
AWS_ACCESS_KEY_NO_PERMISSIONS=[ access key for user with no existing permissions * this needs to be created via AWS console ]
AWS_SECRET_ACCESS_KEY_NO_PERMISSIONS=[ secret for no permissions user  * from AWS console ]
TEST_ROLE_ARN="arn:aws:iam::494226486678:role/pcdc-aws-client-test-role"
USER_NO_PERMISSIONS= [ no permissions user name - created in aws console ]
EMAIL=[ valid email ]
'''

The TEST_ROLE_ARN created via AWS console needs the following permissions:
'''
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "VisualEditor0",
			"Effect": "Allow",
			"Action": [
				"iam:ListUsers",
				"iam:GetUser"
			],
			"Resource": "*"
		}
	]
}
'''

The TEST_ROLE_ARN needs to have the following trust relationship defined under the "trust relationship" tab:
'''
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com",
                "AWS": [ arn for TEST_ROLE_ARN created via AWS in above step ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
'''
# To run tests: 
'''
$ python -m tests.aws-debug
'''
