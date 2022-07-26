from boto3 import client
from boto3.exceptions import Boto3Error
from pcdc_aws_client.boto import BotoManager
import os
import json
from cdislogging import get_logger
import datetime
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_KEY')
REGION_NAME = os.environ.get('REGION_NAME')
BUCKET = os.environ.get('BUCKET')
GROUP_1 = os.environ.get('GROUP_1')
GROUP_2 = os.environ.get('GROUP_2')
USER = os.environ.get('USER')
AWS_ACCESS_KEY_NO_PERMISSIONS = os.environ.get('AWS_ACCESS_KEY_NO_PERMISSIONS')
AWS_SECRET_ACCESS_KEY_NO_PERMISSIONS = os.environ.get('AWS_SECRET_ACCESS_KEY_NO_PERMISSIONS')
TEST_ROLE_ARN = os.environ.get('TEST_ROLE_ARN')
USER_NO_PERMISSIONS = os.environ.get('USER_NO_PERMISSIONS')
EMAIL = os.environ.get('EMAIL')





def test_get_bucket_region(botomanager, bucket, config):
    assert REGION_NAME, botomanager.get_bucket_region(bucket, config)


def test_get_all_groups(botomanager, group_list):
    #list only has preexisting groups
    assert group_list == list(botomanager.get_all_groups(group_list).keys())
    #need to check if it will add groups


def test_get_user_group(botomanager, group_list):
    assert group_list == list(botomanager.get_user_group(group_list).keys())


def test_add_user_to_group(botomanager, group, user):
    group = botomanager.get_all_groups(group)
    botomanager.add_user_to_group(group, user)
    assert USER, botomanager.iam.get_group(GroupName=GROUP_1)['Users'][0]['UserName']
    botomanager.iam.remove_user_from_group(GroupName=GROUP_1, UserName=USER)
    assert '[]', str(botomanager.iam.get_group(GroupName=GROUP_1)['Users'])


def test_create_user_group(botomanager, group_name):
    pass


def test_assume_role(botomanager_paul, botomanager_UserNoPrivileges,
                     config):
    duration_seconds = 900
    arn = TEST_ROLE_ARN
    assert [] == botomanager_paul.iam.list_attached_user_policies(UserName=USER_NO_PERMISSIONS)['AttachedPolicies']
    assume_role_object = botomanager_UserNoPrivileges.assume_role(arn, duration_seconds, config)
    credentials=assume_role_object['Credentials']
    botomanager_UserNoPrivileges.iam = client('iam',
                                aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'],
                                )
    #'UserNoPrivileges' now has access to full IAM control
    botomanager_UserNoPrivileges.iam.get_user(UserName=USER_NO_PERMISSIONS)


def test_delete_data_file(botomanager, bucket, prefix):
    dir = os.path.dirname(__file__)
    hello_path = os.path.join(dir, 'testfiles\hello.txt')
    botomanager.s3_client.upload_file(hello_path, 
                                      bucket, 'hello.txt')
    botomanager.delete_data_file(bucket, prefix='hello.txt')
    """
    test1_path = os.path.join(dir, 'testfiles\test-1.py')
    botomanager.s3_client.upload_file(test1_path, 
                                      bucket, 'test-1.py')
    test2_path = os.path.join(dir, 'testfiles\test-1.py')
    botomanager.s3_client.upload_file(test2_path, 
                                      bucket, 'python/test-2.py')
    botomanager.delete_data_file(bucket, prefix='python/test-1.py')
    botomanager.delete_data_file(bucket, prefix='python/test-2.py')
    """


def test_presigned_url(botomanager, bucket, config):
    print(botomanager.presigned_url(bucket, 'hello.txt', 1000, config))


def test_send_email(botomanager):
    botomanager.send_email(EMAIL, EMAIL,'Test Email', 'This is a test', 'hello', 'ASCII')


def test_initilize_multipart_upload(botomanager):
    return botomanager.initilize_multipart_upload(BUCKET, 'hello', 10)
    
    
def test_complete_multipart_upload(botomanager, url_test=False):
    uploadId = test_initilize_multipart_upload(botomanager)
    parts = []
    uploaded_bytes = 0
    part_bytes = int(15e6)
    dir = os.path.dirname(__file__)
    hello_path = os.path.join(dir, 'testfiles\hello.txt')
    total_bytes = os.stat(hello_path).st_size
    with open(hello_path, "rb") as f:
      i = 1
      while True:
        data = f.read(part_bytes)
        if not len(data):
          break
        part = botomanager.s3_client.upload_part(
            Body=data, Bucket=BUCKET, Key='hello', UploadId=uploadId, PartNumber=i)
        if url_test:
            print(botomanager.generate_presigned_url_for_uploading_part(BUCKET, 'hello', uploadId, i, REGION_NAME, 300))
        parts.append({"PartNumber": i, "ETag": part["ETag"]})
        uploaded_bytes += len(data)
        print("{0} of {1} uploaded ({2:.3f}%)".format(
            uploaded_bytes, total_bytes,
            (float(uploaded_bytes) / float(total_bytes) * 100.0)))
        i += 1
    botomanager.complete_multipart_upload(BUCKET, 'hello', uploadId, parts, 1)

def test_generate_presigned_url_for_uploading_part(botomanager):
    test_complete_multipart_upload(botomanager, url_test=True)


def main():
    logger = get_logger(__name__, log_level='info')

    config= {'AWS_CREDENTIALS': {'CRED1': {'aws_access_key_id': AWS_ACCESS_KEY,
                                           'aws_secret_access_key': AWS_SECRET_ACCESS_KEY,
                                           'region_name': REGION_NAME}}
            }

    #configuration for aws
    if "AWS_CREDENTIALS" in config and len(config["AWS_CREDENTIALS"]) > 0:
        #TODO why does it need to be the first one? (use the key value in the object instead of making it a list)
        value = list(config["AWS_CREDENTIALS"].values())[0]
        test_botomanager = BotoManager(value, logger=logger)
        logger.info("BotoManager initialized")
    else:
        logger.warning("Missing credentials for BotoManager, delivery of data will fail.")
    bucket = BUCKET
    print(GROUP_1)
    group_list = [GROUP_1]


    test_get_bucket_region(test_botomanager, bucket, value)
    test_get_user_group(test_botomanager, group_list)
    test_get_all_groups(test_botomanager, group_list)
    test_add_user_to_group(test_botomanager, group_list, USER)
    test_create_user_group(test_botomanager, GROUP_2)

    #different user with no premissions
    config_test_assume_role=  {'aws_access_key_id': AWS_ACCESS_KEY_NO_PERMISSIONS,
                               'aws_secret_access_key': AWS_SECRET_ACCESS_KEY_NO_PERMISSIONS}
    
    test_assume_role(test_botomanager, BotoManager(config_test_assume_role, logger=logger), 
                     config_test_assume_role)
    
    test_delete_data_file(test_botomanager, bucket, '')
    test_presigned_url(test_botomanager, bucket, value)
    test_send_email(test_botomanager)
    test_initilize_multipart_upload(test_botomanager)
    test_complete_multipart_upload(test_botomanager)
    test_generate_presigned_url_for_uploading_part(test_botomanager)

if __name__ == '__main__':
    main()
