# pcdc-aws-client
Aws client package
AWS client to communicate with S3, SES, iam, sts, ec2, and logs.
to install aws client:
-e git+http://github.com/chicagopcdc/pcdc-aws-client.git@pcdc_dev#egg=aws_client

from aws-client.boto import BotoManager

to run tests:
activate poetry virtual enviorment
fill in information to access aws account
python -m tests.aws-debug