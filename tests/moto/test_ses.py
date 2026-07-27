import pytest
from unittest.mock import MagicMock
from moto import mock_aws

from pcdc_aws_client.boto import BotoManager
from pcdc_aws_client.errors import InternalError


@pytest.fixture
def boto_manager():
    with mock_aws():
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        yield bm

def test_send_email_succeeds_when_sender_is_verified(boto_manager):
    bm = boto_manager
    bm.ses_client.verify_email_identity(EmailAddress="sender@example.com")
    bm.send_email(
        SENDER="sender@example.com",
        RECIPIENT="recipient@example.com",
        SUBJECT="Test",
        BODY_HTML="<p>hello</p>",
    )

def test_send_email_increments_send_quota(boto_manager):
    bm = boto_manager
    bm.ses_client.verify_email_identity(EmailAddress="sender@example.com")
    quota_before = bm.ses_client.get_send_quota()["SentLast24Hours"]
    bm.send_email(
        SENDER="sender@example.com",
        RECIPIENT="recipient@example.com",
        SUBJECT="Test",
        BODY_HTML="<p>hello</p>",
    )
    quota_after = bm.ses_client.get_send_quota()["SentLast24Hours"]
    assert quota_after > quota_before

def test_send_email_raises_internal_error_when_sender_unverified(boto_manager):
    bm = boto_manager
    with pytest.raises(InternalError):
        bm.send_email(
            SENDER="sender@example.com",
            RECIPIENT="recipient@example.com",
            SUBJECT="Test",
            BODY_HTML="<p>hello</p>",
        )

def test_send_email_with_multiple_recipients_and_cc_against_real_ses(boto_manager):
    bm = boto_manager
    bm.ses_client.verify_email_identity(EmailAddress="sender@example.com")
    bm.send_email(
        SENDER="sender@example.com",
        RECIPIENT=["a@example.com", "b@example.com"],
        SUBJECT="Test",
        BODY_HTML="<p>hello</p>",
        CC_RECIPIENTS=["cc@example.com"],
    )