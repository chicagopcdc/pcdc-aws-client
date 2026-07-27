import pytest
from unittest.mock import patch, MagicMock
from pcdc_aws_client.boto import BotoManager

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

def test_create_session_config_passed_profile():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.return_value = mock_session
        config = {"region_name": "us-east-1", "profile_name": "my-profile"}
        BotoManager(config=config, logger=MagicMock())
        MockSession.assert_called_once_with(profile_name="my-profile", region_name="us-east-1")

def test_create_session_config_passed_aws_access_key():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.return_value = mock_session
        config = {"aws_access_key_id": "KSHSSA", "aws_secret_access_key": "lakhjsl34ksj", "region_name": "us-east-1"}
        BotoManager(config=config, logger=MagicMock())
        MockSession.assert_called_once_with(aws_access_key_id="KSHSSA", aws_secret_access_key="lakhjsl34ksj", aws_session_token=None, region_name="us-east-1")

def test_access_key_branch_includes_optional_session_token():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        MockSession.return_value = MagicMock()
        config = {
            "aws_access_key_id": "KSHSSA",
            "aws_secret_access_key": "lakhjsl34ksj",
            "aws_session_token": "temp-token",
            "region_name": "us-east-1"
        }
        
        BotoManager(config=config, logger=MagicMock())

        MockSession.assert_called_once_with(
            aws_access_key_id="KSHSSA",
            aws_secret_access_key="lakhjsl34ksj",
            aws_session_token="temp-token",
            region_name="us-east-1",
        )

def test_create_session_config_passed_region():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.return_value = mock_session
        config = {"region_name": "us-east-1"}
        BotoManager(config=config, logger=MagicMock())
        MockSession.assert_called_once_with(region_name="us-east-1")

def test_create_session_error_raised():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.side_effect = Exception("exception")
        mock_logger = MagicMock()
        with pytest.raises(Exception):
            BotoManager(config={"region_name": "us-east-1"}, logger=mock_logger)

        mock_logger.error.assert_called_once()

def test_get_client_calls_session(boto_manager):
    bm, mock_session = boto_manager
    mock_session.client.reset_mock()
    result = bm.get_client("mydbservice")
    mock_session.client.assert_called_once_with("mydbservice")
    assert(result is mock_session.client.return_value)

def test_get_resource_calls_session(boto_manager):
    bm, mock_session = boto_manager
    mock_session.resource.reset_mock()
    result = bm.get_resource("mydbresource")
    mock_session.resource.assert_called_once_with("mydbresource")
    assert(result is mock_session.resource.return_value)

