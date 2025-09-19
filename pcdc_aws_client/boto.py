import json
import tempfile
import time
import uuid
from io import StringIO

import html2text
import requests
from boto3 import Session, client, resource
from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError
from cdispyutils.hmac4 import generate_aws_presigned_url
from retry.api import retry_call

from .errors import InternalError, NotFound, UnavailableError, UserError


class BotoManager(object):
    """
    AWS manager singleton.
    """

    URL_EXPIRATION_DEFAULT = 1800  # 30 minutes
    URL_EXPIRATION_MAX = 86400  # 1 day

    def __init__(self, config=None, logger=None):
        """
        need config which includes aws access and secret access keys and other information like region
        depending on what aws tools are going to be used. 
        """
        self.logger = logger
        self.config = config or {}

        self.session = self._create_session(self.config)
        self._init_clients()

    def _create_session(self, config):
        """
        Create a boto3 Session based on available config:
        - profile_name: uses named profile from ~/.aws/config
        - aws_access_key_id & aws_secret_access_key: direct credentials
        - fallback to default session (e.g., IAM role)
        """
        try:
            if 'profile_name' in config:
                return Session(profile_name=config['profile_name'], region_name=config.get('region_name'))
            elif 'aws_access_key_id' in config and 'aws_secret_access_key' in config:
                return Session(
                    aws_access_key_id=config['aws_access_key_id'],
                    aws_secret_access_key=config['aws_secret_access_key'],
                    aws_session_token=config.get('aws_session_token'),  # optional
                    region_name=config.get('region_name')
                )
            else:
                return Session(region_name=config.get('region_name'))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create AWS session: {e}")
            raise

    def _init_clients(self):
        self.s3_client = self.session.client('s3')
        self.s3_resource = self.session.resource('s3')
        self.sts_client = self.session.client("sts")
        self.iam = self.session.client('iam')
        self.ses_client = self.session.client('ses')
        self.ec2_client = self.session.client('ec2')
        self.ec2_resource = self.session.resource('ec2')
        self.logs_client = self.session.client('logs')
        self.batch_client = self.session.client('batch')
        self.secrets_client = self.session.client('secretsmanager')
        self.ssm_client = self.session.client('ssm')

    def get_client(self, service_name):
        """Dynamically get a client for any AWS service."""
        return self.session.client(service_name)

    def get_resource(self, service_name):
        """Dynamically get a resource for any AWS service."""
        return self.session.resource(service_name)


    def delete_data_file(self, bucket, prefix):
        """
        delete a file from a s3 bucket need bucket and file path

        We use buckets with versioning disabled.

        See AWS docs here:

            https://docs.aws.amazon.com/AmazonS3/latest/dev/DeletingObjectsfromVersioningSuspendedBuckets.html
        """
        try:
            s3_objects = self.s3_client.list_objects_v2(
                Bucket=bucket, Prefix=prefix, Delimiter="/"
            )

            if not s3_objects.get("Contents"):
                # file not found in the bucket
                self.logger.info(
                    "tried to delete prefix {} but didn't find in bucket {}".format(
                        prefix, bucket
                    )
                )
                return (
                    "Unable to delete the data file associated with this record. Backing off.",
                    404,
                )
            if len(s3_objects["Contents"]) > 1:
                self.logger.error("multiple files found with prefix {}".format(prefix))
                return ("Multiple files found matching this prefix. Backing off.", 400)
            key = s3_objects["Contents"][0]["Key"]
            self.s3_client.delete_object(Bucket=bucket, Key=key)
            self.logger.info(
                "deleted file for prefix {} in bucket {}".format(prefix, bucket)
            )
            return ("", 204)
        except (KeyError, Boto3Error) as e:
            self.logger.error("Failed to delete file: {}".format(str(e)))
            return ("Unable to delete data file.", 500)

    def assume_role(self, role_arn, duration_seconds, config=None):
        """
        allow user to change aws roles for some time
        """
        assert (
            duration_seconds
        ), 'assume_role() cannot be called without "duration_seconds" parameter; please check your "expires_in" parameters'
        try:
            if config and "aws_access_key_id" in config:
                self.sts_client = client("sts", **config)
            session_name_postfix = uuid.uuid4()
            return self.sts_client.assume_role(
                RoleArn=role_arn,
                DurationSeconds=duration_seconds,
                RoleSessionName="{}-{}".format("gen3", session_name_postfix),
            )
        except Boto3Error as ex:
            self.logger.exception(ex)
            raise InternalError("Fail to assume role: {}".format(ex))
        except Exception as ex:
            self.logger.exception(ex)
            raise UnavailableError("Fail to reach AWS: {}".format(ex))

    def presigned_url(self, bucket, key, expires, config, method="get_object", dummy_s3=False):
        """
        Args:
            bucket (str): bucket name
            key (str): key in bucket
            expires (int): presigned URL expiration time, in seconds
            config (dict): additional parameters if necessary (e.g. updating access key)
            method (str): "get_object" or "put_object" (ClientMethod argument to boto)
        """
        if method not in ["get_object", "put_object"]:
            raise UserError("method {} not allowed".format(method))
        if "aws_access_key_id" in config:
            self.s3_client = client("s3", **config)

        expires = int(expires) if expires and int(expires) else self.URL_EXPIRATION_DEFAULT
        expires = min(expires, self.URL_EXPIRATION_MAX)
        params = {"Bucket": bucket, "Key": key}

        # check if object exists when not using dummy s3 bucket
        if not dummy_s3:
            if method == "get_object":
                try:
                    response = self.s3_client.get_object(Bucket=bucket, Key=key)
                except Exception as e:
                    self.logger.exception(e)
                    raise NotFound("Could not locate file")

        if method == "put_object":
            params["ServerSideEncryption"] = "AES256"

        try:
            return self.s3_client.generate_presigned_url(
                ClientMethod=method, Params=params, ExpiresIn=expires
            )
        except Exception as ex:
            self.logger.exception(ex)
            raise InternalError("Failed to get pre-signed url")


    def get_bucket_region(self, bucket, config):
        """
        get region for a specfic aws bucket
        """
        try:
            if "aws_access_key_id" in config:
                self.s3_client = client("s3", **config)
            response = self.s3_client.get_bucket_location(Bucket=bucket)
            region = response.get("LocationConstraint")
        except Boto3Error as ex:
            self.logger.exception(ex)
            raise InternalError("Fail to get bucket region: {}".format(ex))
        except Exception as ex:
            self.logger.exception(ex)
            raise UnavailableError("Fail to reach AWS: {}".format(ex))
        if region is None:
            return "us-east-1"
        return region

    def get_all_groups(self, list_group_name):
        """
        Get all groups listed in the list_group_name.
        If group does not exist, add as new group and include in the return list
        :param list_group_name:
        :return:
        """
        try:
            groups = self.get_user_group(list_group_name)
            if len(groups) < len(list_group_name):
                for group_name in list_group_name:
                    if group_name not in groups:
                        groups[group_name] = self.create_user_group(group_name)
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create list of groups: {}".format(ex))
        return groups

    def add_user_to_group(self, groups, username):
        """
        Add user to the list of group which have association membership.
        :param groups:
        :param username:
        :return:
        """
        try:
            for group in list(groups.values()):
                self.iam.add_user_to_group(
                    GroupName=group["GroupName"], UserName=username
                )
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to add user to group: {}".format(ex))

    def get_user_group(self, group_names):
        """
        return name of groups that exist from group_names
        """
        try:
            groups = self.iam.list_groups()["Groups"]
            res = {}
            for group in groups:
                if group["GroupName"] in group_names:
                    res[group["GroupName"]] = group
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to get list of groups {}: {}".format(group_names, ex))
        return res

    def create_user_group(self, group_name, path=None):
        """
        create a group
        """
        try:
            group = self.iam.create_group(GroupName=group_name)["Group"]
            self.__create_policy__(
                group_name, self.__get_policy_document_by_group_name__(group_name)
            )
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create group {}: {}".format(group_name, ex))
        return group

    def __get_policy_document_by_group_name__(self, group_name):
        """
        Getting policy document from config file and replace with actual value (same as project name)
        :param group_name:
        :return:
        """
        pass

    def __fill_with_new_value__(self, document, value):
        pass

    def __create_policy__(
        self, policy_name, policy_document, path=None, description=None
    ):
        """
        Create policy with name and policies specified in policy_document.
        :param policy_name: Name of policy in AWS.
        :param policy_document: Document specified the policy rule.
        :param path:
        :param description:
        :return:
        """
        try:
            aws_kwargs = dict(Path=path, Description=description)
            aws_kwargs = {k: v for k, v in list(aws_kwargs.items()) if v is not None}
            policy = self.iam.create_policy(
                PolicyName=policy_name, PolicyDocument=policy_document, **aws_kwargs
            )
            self.iam.attach_group_policy(
                GroupName=policy_name, PolicyArn=policy["Policy"]["Arn"]
            )
        except Exception as ex:
            self.logger.exception(ex)
            raise UserError("Fail to create policy: {}".format(ex))
        return policy

    # gen3_scripts\check_vpn_restricted\sendEmail.py
    # gen3_scripts\slackUpdates\sendEmail.py
    # fence\utils.py
    def send_email(
        self,
        SENDER,
        RECIPIENT,
        SUBJECT,
        BODY_HTML,
        CHARSET="UTF-8",
        BODY_TEXT=None,
        CC_RECIPIENTS=None,
        CONFIGURATION_SET=None,
        config=None,
    ):
        if config:
            self.ses_client = client('ses', **config)
        if not BODY_TEXT:
            BODY_TEXT = html2text.html2text(BODY_HTML)
        RECIPIENTS = []
        if isinstance(RECIPIENT, list):
            RECIPIENTS = RECIPIENT
        else:
            RECIPIENTS.append(RECIPIENT)

        #CC_RECIPIENTS is either a string of one email of a list of strings containing emails
        #1) CC_RECIPIENTS = "email1@uchicago"
        #2) CC_RECIPIENTS = ["email1@uchicago", "email2@uchicago"]
        CC_RECIPIENTS_LIST = []
        if CC_RECIPIENTS:
            if isinstance(CC_RECIPIENTS, list):
                CC_RECIPIENTS_LIST = CC_RECIPIENTS
            else:
                CC_RECIPIENTS_LIST.append(CC_RECIPIENTS)
        try:
		#Provide the contents of the email.
            response = self.ses_client.send_email(
                Destination={
                    'ToAddresses': RECIPIENTS,
                    'CcAddresses': CC_RECIPIENTS_LIST,
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': BODY_HTML,
                        },
                        'Text': {
                            'Charset': CHARSET,
                            'Data': BODY_TEXT,
                        },
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': SUBJECT,
                    },
                },
                Source=SENDER,
                    # If you are not using a configuration set, comment or delete the
                    # following line
                    #ConfigurationSetName=CONFIGURATION_SET,
		)
        # Display an error if something goes wrong.	
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['MessageId'])


    # #gen3_scripts\cloudwatch\get_logs_survival.py
    def get_logs(self, env_group_name, epoch_start, epoch_end, queryString):
        try:
            #start the query
            res = self.logs_client.start_query(
                logGroupName=env_group_name,
                startTime=epoch_start,
                endTime=epoch_end,
                queryString=queryString,
                limit=10000
            )
            # print(res)

            queryId=res["queryId"]

            # get the response
            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/logs.html#CloudWatchLogs.Client.get_query_results
            response = self.logs_client.get_query_results(
                queryId=queryId
            )
            while response["status"] != "Complete":
                print(response["status"] + "...")
                if response["status"] == "Cancelled" or response["status"] =="Failed" or response["status"] == "Timeout" or response["status"] =="Unknown":
                    print(response)
                    print("your queryId is: " + queryId + ". Please Check on the AWS console if the description in the response above is not helpful.")
                    exit()
                print("hang in there while AWS is searching...")
                time.sleep(60)
                response = self.logs_client.get_query_results(
                    queryId=queryId
                )
            # print(response["results"])
            # print(len(response["results"]))
    
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            # print(response)
            return response

    #fence\blueprints\data\multipart_upload.py
    def initilize_multipart_upload(self, bucket, key, MAX_TRIES):
        try:
            multipart_upload = retry_call(
                self.s3_client.create_multipart_upload,
                fkwargs={"Bucket": bucket, "Key": key},
                tries=MAX_TRIES,
                jitter=10,
            )
        except ClientError as error:
            logger.error(
                "Error when create multiple part upload for object with uuid {}. Detail {}".format(
                    key, error
                )
            )
            raise InternalError("Can not initilize multipart upload for {}".format(key))

        return multipart_upload.get("UploadId")

    #fence\blueprints\data\multipart_upload.py
    def complete_multipart_upload(self, bucket, key, uploadId, parts, MAX_TRIES):
        try:
            retry_call(
                self.s3_client.complete_multipart_upload,
                fkwargs={
                    "Bucket": bucket,
                    "Key": key,
                    "MultipartUpload": {"Parts": parts},
                    "UploadId": uploadId,
                },
                tries=MAX_TRIES,
                jitter=10,
            )
        except ClientError as error:
            self.logger.error(
                "Error when completing multiple part upload for object with uuid {}. Detail {}".format(
                    key, error
                )
            )
            raise InternalError(
                "Can not complete multipart upload for {}. Detail {}".format(key, error)
            )
    
    def generate_presigned_url_for_uploading_part(bucket, key, uploadId, partNumber, region, expires, credentials=None):
        """
        Generate presigned url for uploading object part given uploadId and part number

        Args:
            bucket(str): bucket
            key(str): key
            credentials(dict): dictionary of aws credentials
            uploadId(str): uploadID of the multipart upload
            partNumber(int): part number
            region(str): bucket region
            expires(int): expiration time

        Returns:
            presigned_url(str)
        """
        if not credentials:
            credentials = self.config

        url = "https://{}.s3.amazonaws.com/{}".format(bucket, key)
        additional_signed_qs = {"partNumber": str(partNumber), "uploadId": uploadId}

        try:
            return generate_aws_presigned_url(
                url, "PUT", credentials, "s3", region, expires, additional_signed_qs
            )
        except Exception as e:
            raise InternalError(
                "Can not generate presigned url for part number {} of key {}. Detail {}".format(
                    partNumber, key, e
                )
            )

    def get_vpc_nat_gateway_ips(self, vpc_name):
        if not vpc_name:
            self.logger.error("No VPC name provided")
            return []
        response = self.ec2_client.describe_vpcs(
            Filters=[
                {'Name': 'tag:Name', 'Values': [vpc_name]}
            ]
        )

        # Check if the VPC was found
        if not response['Vpcs']:
            self.logger.info(f"VPC named {vpc_name} not found.")
            return []
        else:
            vpc_id = response['Vpcs'][0]['VpcId']
            self.logger.info(f"VPC ID for {vpc_name}: {vpc_id}")

            # Describe NAT Gateways for the specified VPC
            nat_gateways_response = self.ec2_client.describe_nat_gateways(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
        public_ips = []
        # Check if any NAT Gateways were found
        if not nat_gateways_response['NatGateways']:
            self.logger.info("No NAT Gateways found in VPC {vpc_name}.")
        else:
            for nat_gateway in nat_gateways_response['NatGateways']:
                nat_gateway_id = nat_gateway['NatGatewayId']
                for address in nat_gateway['NatGatewayAddresses']:
                    public_ip = address.get('PublicIp')
                    if public_ip:
                        self.logger.info(f"NAT Gateway ID: {nat_gateway_id}, Public IP: {public_ip}")
                        public_ips.append(public_ip + '/32')
        
        return public_ips
    
    def get_ec2_public_ips_by_name(self, name):
        response = self.ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [f'*{name}*']
                }
            ]
        )

        public_ips = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if 'PublicIpAddress' in instance:
                    public_ips.append(instance['PublicIpAddress'] + '/32')

        return public_ips

    def restrict_sc(self, SECURITY_GROUP_ID, restricted_ips):
        security_group = self.ec2_resource.SecurityGroup(SECURITY_GROUP_ID)
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
            #print(response)
            ip_dict = {}
            for sc in response["SecurityGroups"]:
                for p in sc["IpPermissions"]:
                    #print(p)
                    for ip in p["IpRanges"]:
                        #print(ip)
                        if ip["CidrIp"] not in ip_dict:
                            ip_dict[ip["CidrIp"]] = []
                        ip_dict[ip["CidrIp"]].append({"protocol": p["IpProtocol"], "port": p["FromPort"]})

            # print(ip_dict)
            # {'0.0.0.0/0': [{'protocol': 'tcp', 'port': 80}, {'protocol': 'icmp', 'port': 3}, {'protocol': 'tcp', 'port': 443}]}

            # REMOVE HTTP OPEN ACCESS
            if "0.0.0.0/0" in ip_dict:
                        ip_extract = [i for i in ip_dict["0.0.0.0/0"] if i["protocol"] == "tcp" and (i["port"] == 80 or i["port"] == 443)]
                        for i in ip_extract:
                                security_group.revoke_ingress(IpProtocol=i["protocol"], CidrIp="0.0.0.0/0", FromPort=i["port"], ToPort=i["port"])
                                # print(i)

            # ADD LIMITED HTTP ACCESS BY UCHICAGO VPN and ETL VM
            for ip in restricted_ips:
                if ip not in ip_dict:
                    security_group.authorize_ingress(IpProtocol="tcp",CidrIp=ip,FromPort=80,ToPort=80)
                    security_group.authorize_ingress(IpProtocol="tcp",CidrIp=ip,FromPort=443,ToPort=443)
                    # print(ip)
                else:
                    skip_80 = False
                    skip_443 = False
                    for i in ip_dict[ip]:
                        if i["protocol"] == "tcp":
                            if i["port"] == 80:
                                skip_80 = True
                            if i["port"] == 443:
                                skip_443 = True
                    if not skip_80:
                        security_group.authorize_ingress(IpProtocol="tcp",CidrIp=ip,FromPort=80,ToPort=80)

                    if not skip_443:
                        security_group.authorize_ingress(IpProtocol="tcp",CidrIp=ip,FromPort=443,ToPort=443)


        except ClientError as e:
            print(e)

    def get_object(self, bucket, key, expires, config, returnJson=True): 
        """
        Args:
            bucket (str): bucket name
            key (str): key in bucket
            expires (int): presigned URL expiration time, in seconds
            config (dict): additional parameters if necessary (e.g. updating access key)
        """
        try:
            url = self.presigned_url(bucket, key, expires, config)
        except Exception as ex:
            self.logger.exception(ex)
            raise InternalError(f"Failed to get pre-signed url for get_object: {ex}")

        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.exceptions.HTTPError as ex:
            self.logger.info(
                "HTTP Error {} fetching bucket {} key {}".format(
                    ex, bucket, key
                )
            )
            raise NotFound("Failed to get object: {} from bucket: {} exception: {}".format(key, bucket, ex))
        except Exception as ex:
            self.logger.exception(ex)
            raise InternalError("Failed to get object: {} from bucket: {} exception: {}".format(key, bucket, ex))

        if returnJson:
            return response.json()
        else:
            return response

    def put_object(self, bucket, key, expires, config, contents): 
        """
        This function creates and uploads string or json to an s3 bucket 
        Args:
            bucket (str): bucket name
            key (str): key in bucket
            expires (int): presigned URL expiration time, in seconds
            config (dict): additional parameters if necessary (e.g. updating access key)
            contents: text or json content
        """
        try:
            url_info = self.s3_client.generate_presigned_post(Bucket = bucket, Key = key, ExpiresIn = 30)
        except Exception as ex:
            self.logger.exception(ex)
            raise InternalError("Failed to generate presigned post url: {}".format(ex))

        with tempfile.NamedTemporaryFile(mode="w+") as f:
            if type(contents) is str:
                f.write(contents)
            else:
                json.dump(contents, f)
            f.flush()
            f.seek(0)
            try:
                post_url = url_info['url']
                data = url_info['fields']
                response = requests.post(post_url, data, files={'file':f})
                response.raise_for_status()
            except requests.exceptions.HTTPError as ex:
                self.logger.info(
                    "HTTP Error {} fetching bucket {} key {}".format(
                        ex, bucket, key
                    )
                )
                raise InternalError("Failed to put object: {} in bucket: {} exception: {}".format(key, bucket, ex))

            except Exception as ex:
                raise InternalError("Post failed key: {} bucket: {} exception: {}".format(key, bucket,ex))


    def load_csv_from_s3(s3_bucket_name, s3_key="cache/cache.csv"):
        try:
            obj = s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
            content = obj["Body"].read().decode("utf-8")
            reader = csv.DictReader(StringIO(content))
            return list(reader)
        except s3_client.exceptions.NoSuchKey:
            print(f"No cache found at s3://{s3_bucket_name}/{s3_key}")
            return []

    def upload_csv_content_to_s3(rows, s3_bucket_name, s3_key="cache/cache.csv"):
        """
        Uploads a list of dicts as CSV directly to S3 without creating a local file.
        """
        # Write CSV to an in-memory string
        output = StringIO()
        fieldnames = rows[0].keys() if rows else ["user_id", "timestamp", "raw"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

        # Upload string content to S3
        s3_client.put_object(Bucket=s3_bucket_name, Key=s3_key, Body=output.getvalue().encode("utf-8"))
        print(f"Uploaded {len(rows)} rows directly to s3://{s3_bucket_name}/{s3_key}")

    def get_list_files_in_s3_folder(self, bucket_name, folder_path, uri_type="s3a"):
        """
        """
        bucket = self.s3_resource.Bucket(bucket_name)

        files = []
        for object_summary in bucket.objects.filter(Prefix=folder_path):
            # print(object_summary.key)
            # files.append(uri_type + "://" + bucket_name + "/" + object_summary.key)
            files.append(object_summary.key)

        return files

    def get_secret(self, secret_name):
        try:
            get_secret_value_response = self.secrets_client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            raise e

        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response['SecretString']
        return secret

    def get_param_from_ssm(self, parameter_name):
        try:
            # Get credentials from AWS SSM Parameter Store
            param = self.ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        except ClientError as e:
            raise e

        param = json.loads(param["Parameter"]["Value"])
        return param

    def submit_batch_job(self, job_definition, job_name, job_queue, container_overrides={}):
        try:
            response = self.batch_client.submit_job(
                jobDefinition=job_definition,
                jobName=job_name,
                jobQueue=job_queue,
                containerOverrides=container_overrides
            )
            print(response)
        except ClientError as e:
            raise e

        return response








