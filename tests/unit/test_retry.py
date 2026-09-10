import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from pcdc_aws_client.errors import InternalError


def make_client_error(message="Errors"):
    return ClientError(
        error_response={"Error": {"Code": "Exception", "Message": message}},
        operation_name="CreateMultipartUpload",
    )

#initialize multipart upload
def test_initilize_multipart_upload_calls_retry_call_with_correct_args(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    with patch("pcdc_aws_client.boto.retry_call") as mock_retry_call:
        mock_retry_call.return_value = {"UploadId": "upload-123"}
        result = bm.initilize_multipart_upload("my-bucket", "my-key", MAX_TRIES=3)
        mock_retry_call.assert_called_once_with(
            s3_client.create_multipart_upload,
            fkwargs={"Bucket": "my-bucket", "Key": "my-key"},
            tries=3,
            jitter=10,
        )
        assert result == "upload-123"

def test_initilize_multipart_upload_succeeds_after_failures(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.create_multipart_upload.side_effect = [
        make_client_error(),
        make_client_error(),
        {"UploadId": "upload-456"},
    ]
    with patch("time.sleep", return_value=None):
        upload_id = bm.initilize_multipart_upload("my-bucket", "my-key", MAX_TRIES=3)
    assert upload_id == "upload-456"
    assert s3_client.create_multipart_upload.call_count == 3

def test_initilize_multipart_upload_raises_internal_error(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.create_multipart_upload.side_effect = make_client_error()
    with patch("time.sleep", return_value=None):
        with pytest.raises(InternalError):
            bm.initilize_multipart_upload("my-bucket", "my-key", MAX_TRIES=2)
    assert s3_client.create_multipart_upload.call_count == 2

#complete multipart upload
def test_complete_multipart_upload_calls_retry_call_with_correct_args(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    parts = [{"ETag": "part", "PartNumber": 1}]
    with patch("pcdc_aws_client.boto.retry_call") as mock_retry_call:
        bm.complete_multipart_upload("my-bucket", "my-key", "upload-123", parts, MAX_TRIES=3)
        mock_retry_call.assert_called_once_with(
            s3_client.complete_multipart_upload,
            fkwargs={
                "Bucket": "my-bucket",
                "Key": "my-key",
                "MultipartUpload": {"Parts": parts},
                "UploadId": "upload-123",
            },
            tries=3,
            jitter=10,
        )

def test_complete_multipart_upload_raises_internal_error(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.complete_multipart_upload.side_effect = make_client_error("Parts mismatch")
    parts = [{"ETag": "part", "PartNumber": 1}]
    with patch("time.sleep", return_value=None):
        with pytest.raises(InternalError, match="Parts mismatch"):
            bm.complete_multipart_upload("my-bucket", "my-key", "upload-123", parts, MAX_TRIES=2)
    assert s3_client.complete_multipart_upload.call_count == 2
