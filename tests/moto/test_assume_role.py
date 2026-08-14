from datetime import datetime, timedelta, timezone
import pytest
from unittest.mock import MagicMock
from moto import mock_aws
from pcdc_aws_client.boto import BotoManager

@pytest.fixture
def boto_manager():
    with mock_aws():
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        bm.s3_client.create_bucket(Bucket="test-bucket")
        yield bm

# assume_role
def test_assume_role_returns_temporary_credentials(boto_manager):
    bm = boto_manager
    role = bm.iam.create_role(
        RoleName="test-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )
    result = bm.assume_role(role["Role"]["Arn"])
    assert "Credentials" in result
    assert "AccessKeyId" in result["Credentials"]
    assert "SecretAccessKey" in result["Credentials"]

def test_assume_role_session_name_is_unique_per_call(boto_manager):
    """A uuid postfix is appended to role_session_name on every call --
    confirms two calls don't collide even with identical inputs."""
    bm = boto_manager
    role = bm.iam.create_role(
        RoleName="test-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )
    result1 = bm.assume_role(role["Role"]["Arn"])
    result2 = bm.assume_role(role["Role"]["Arn"])
    assert (
        result1["AssumedRoleUser"]["AssumedRoleId"]
        != result2["AssumedRoleUser"]["AssumedRoleId"]
    )

def test_assume_role_respects_duration_seconds(boto_manager):
    bm = boto_manager
    role = bm.iam.create_role(
        RoleName="test-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}',
    )
    before = datetime.now(timezone.utc)

    result = bm.assume_role(
        role["Role"]["Arn"], duration_seconds=900
    )
    
    after = datetime.now(timezone.utc)

    expiration = result["Credentials"]["Expiration"]

    expected_min = before + timedelta(seconds=900)
    expected_max = after + timedelta(seconds=900)

    assert expected_min <= expiration <= expected_max
