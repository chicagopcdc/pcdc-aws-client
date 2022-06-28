from cdislogging import get_logger


logger = get_logger(__name__)


def get_s3_key_and_bucket(url):
	bucket_value_list = url.split(".s3.amazonaws.com/",1)
	if len(bucket_value_list) != 2:
		logger.info("Error in extracting the key information")
		return None

	key = bucket_value_list[1]

	bucket_list = bucket_value_list[0].split("https://",1)
	if len(bucket_list) != 2:
		logger.info("Error in extracting the bucket information")
		return None

	bucket = bucket_list[1]

	return {"key": key, "bucket": bucket}

    