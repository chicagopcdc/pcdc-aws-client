import pytest
from unittest.mock import MagicMock
from moto import mock_aws
from pcdc_aws_client.boto import BotoManager


@pytest.fixture
def boto_manager():
    """Builds a BotoManager inside a moto mock_aws context without hitting AWS."""
    with mock_aws():
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        yield bm
