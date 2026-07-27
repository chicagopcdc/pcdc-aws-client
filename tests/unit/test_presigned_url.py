import pytest
from unittest.mock import patch, MagicMock
from pcdc_aws_client.boto import BotoManager
from pcdc_aws_client.errors import InternalError, NotFound, UnavailableError, UserError

@pytest.fixture
def boto_manager():
    '''
    builds a botomanager without hitting AWS
    '''
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.return_value = mock_session
        bm = BotoManager(config = {"region_name": "us-east-1"}, logger=MagicMock())
        yield bm, mock_session

def test_invalid_method(boto_manager):
    bm, _ = boto_manager
    with pytest.raises(UserError):
        bm.presigned_url("my-bucket", "my-key", 300, {}, method="delete_object")

def test_config_with_access_key_adds_client(boto_manager):
    bm, _ = boto_manager
    config = {"aws_access_key_id": "KSHSSA", "aws_secret_access_key": "lakhjsl34ksj"}
    with patch("pcdc_aws_client.boto.client") as mock_client:
        new_client = MagicMock()
        mock_client.return_value = new_client
        bm.presigned_url("my-bucket", "my-key", 300, config, dummy_s3=True)
        mock_client.assert_called_once_with("s3", **config)


def test_default_expiration(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    bm.presigned_url("my-bucket", "my-key", expires=None, config={}, dummy_s3=True)
    _, kwargs = s3_client.generate_presigned_url.call_args
    assert kwargs["ExpiresIn"] == BotoManager.URL_EXPIRATION_DEFAULT

def test_expiration_max(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    bm.presigned_url("my-bucket", "my-key", 10000000, {}, dummy_s3=True)
    _, kwargs = s3_client.generate_presigned_url.call_args
    assert kwargs["ExpiresIn"] == BotoManager.URL_EXPIRATION_MAX

def test_get_object(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    s3_client.get_object.return_value = {"Body": MagicMock()}
    bm.presigned_url("my-bucket", "my-key", 300, {}, method="get_object")
    s3_client.get_object.assert_called_once_with(Bucket="my-bucket", Key="my-key")
    s3_client.generate_presigned_url.assert_called_once()

def test_get_object_raise_not_found(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    s3_client.get_object.side_effect = Exception("exception")
    with pytest.raises(NotFound):
        bm.presigned_url("my-bucket", "my-key", 300, {})
    s3_client.generate_presigned_url.assert_not_called()

def test_dummy_skips_get_object(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    bm.presigned_url("my-bucket", "my-key", 300, {}, dummy_s3=True)
    s3_client.get_object.assert_not_called()
    s3_client.generate_presigned_url.assert_called_once()

def test_put_object(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    bm.presigned_url("my-bucket", "my-key", 300, {}, method="put_object", dummy_s3=True)
    _, kwargs = s3_client.generate_presigned_url.call_args
    assert kwargs["Params"]["ServerSideEncryption"] == "AES256"
    s3_client.get_object.assert_not_called()

def test_presigning_failure_raises_internal_error(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    s3_client.generate_presigned_url.side_effect = Exception("aws sdk error")

    with pytest.raises(InternalError):
        bm.presigned_url("my-bucket", "my-key", 300, {}, method="get_object", dummy_s3=True)

def test_return_on_success(boto_manager):
    bm, mock_session = boto_manager
    s3_client = mock_session.client.return_value
    s3_client.generate_presigned_url.return_value = "https://my-bucket.s3.amazonaws.com/my-key/saerefs"
    result = bm.presigned_url("my-bucket", "my-key", 300, {}, method="get_object", dummy_s3=True)
    assert result == "https://my-bucket.s3.amazonaws.com/my-key/saerefs"