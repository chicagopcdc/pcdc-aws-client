import json
import pytest
from unittest.mock import MagicMock, patch
import requests

from pcdc_aws_client.errors import NotFound, InternalError


FAKE_PRESIGNED_URL = "https://test-bucket.s3.amazonaws.com/my-key?sig=abc"

#get object
def test_get_object_returns_parsed_json_by_default(boto_manager):
    bm, _ = boto_manager
    with patch.object(bm, "presigned_url", return_value=FAKE_PRESIGNED_URL):
        with patch("pcdc_aws_client.boto.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = {"foo": "bar"}
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            result = bm.get_object("test-bucket", "my-key", 300, {})
            mock_get.assert_called_once_with(FAKE_PRESIGNED_URL)
            assert result == {"foo": "bar"}

def test_get_object_returns_raw_response_when_return_json_false(boto_manager):
    bm, _ = boto_manager
    with patch.object(bm, "presigned_url", return_value=FAKE_PRESIGNED_URL):
        with patch("pcdc_aws_client.boto.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            result = bm.get_object("test-bucket", "my-key", 300, {}, returnJson=False)
            mock_response.json.assert_not_called()
            assert result is mock_response

def test_get_object_raises_not_found_on_http_error(boto_manager):
    bm, _ = boto_manager
    with patch.object(bm, "presigned_url", return_value=FAKE_PRESIGNED_URL):
        with patch("pcdc_aws_client.boto.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404")
            mock_get.return_value = mock_response
            with pytest.raises(NotFound):
                bm.get_object("test-bucket", "missing-key", 300, {})

def test_get_object_raises_internal_error_when_presigning_fails(boto_manager):
    bm, _ = boto_manager
    with patch.object(bm, "presigned_url", side_effect=Exception("presign failed")):
        with pytest.raises(InternalError):
            bm.get_object("test-bucket", "my-key", 300, {})

#put object
def test_put_object_posts_contents_as_string(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.generate_presigned_post.return_value = {
        "url": "https://test-bucket.s3.amazonaws.com/",
        "fields": {"key": "my-key", "policy": "abc"},
    }

    with patch("pcdc_aws_client.boto.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        bm.put_object("test-bucket", "my-key", 300, {}, contents="hello world")

        s3_client.generate_presigned_post.assert_called_once_with(
            Bucket="test-bucket", Key="my-key", ExpiresIn=30
        )
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://test-bucket.s3.amazonaws.com/"
        assert args[1] == {"key": "my-key", "policy": "abc"}
        assert "file" in kwargs["files"]

def test_put_object_raises_internal_error_on_http_error(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.generate_presigned_post.return_value = {
        "url": "https://test-bucket.s3.amazonaws.com/",
        "fields": {"key": "my-key"},
    }

    with patch("pcdc_aws_client.boto.requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("403")
        mock_post.return_value = mock_response
        with pytest.raises(InternalError):
            bm.put_object("test-bucket", "my-key", 300, {}, contents="hello")

def test_put_object_raises_internal_error_presigned_post_fail(boto_manager):
    bm, _ = boto_manager
    s3_client = bm.s3_client
    s3_client.generate_presigned_post.side_effect = Exception("boom")
    with pytest.raises(InternalError):
        bm.put_object("test-bucket", "my-key", 300, {}, contents="hello")
