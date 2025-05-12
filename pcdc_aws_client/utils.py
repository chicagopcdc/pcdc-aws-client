from cdislogging import get_logger
import re

logger = get_logger(__name__)


def get_s3_key_and_bucket(url):
	pattern = r"https://([^.]+)\.s3(?:\.[^.]*)?\.amazonaws\.com/(.+)"

	match = re.match(pattern, url)
	if not match:
		logger.error("Error in extracting bucket and key from URL.")
		return None

	bucket = match.group(1)
	key = match.group(2)

	return {"key": key, "bucket": bucket}
    