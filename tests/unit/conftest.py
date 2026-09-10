import pytest
from unittest.mock import MagicMock, patch
from pcdc_aws_client.boto import BotoManager


@pytest.fixture
def boto_manager():
    """Builds a BotoManager with a mocked Session.

    Yields (bm, mock_session). Each AWS service client gets its own distinct
    MagicMock via side_effect, so a side_effect set on bm.s3_client cannot
    accidentally bleed into bm.logs_client or other clients.
    """
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        _clients = {}

        def _make_client(service):
            return _clients.setdefault(service, MagicMock(name=f"mock_{service}"))

        mock_session.client.side_effect = _make_client
        MockSession.return_value = mock_session
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        yield bm, mock_session
