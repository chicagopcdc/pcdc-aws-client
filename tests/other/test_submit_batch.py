import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from pcdc_aws_client.boto import BotoManager


@pytest.fixture
def boto_manager():
    with patch("pcdc_aws_client.boto.Session") as MockSession:
        mock_session = MagicMock()
        MockSession.return_value = mock_session
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        yield bm, mock_session

def test_submit_batch_job_calls_submit_job_with_correct_args(boto_manager):
    bm, mock_session = boto_manager
    batch_client = mock_session.client.return_value
    batch_client.submit_job.return_value = {"jobId": "job-123", "jobName": "my-job"}
    result = bm.submit_batch_job("my-job-def", "my-job", "my-queue")
    batch_client.submit_job.assert_called_once_with(
        jobDefinition="my-job-def",
        jobName="my-job",
        jobQueue="my-queue",
        containerOverrides={},
    )
    assert result == {"jobId": "job-123", "jobName": "my-job"}

def test_submit_batch_job_passes_through_container_overrides(boto_manager):
    bm, mock_session = boto_manager
    batch_client = mock_session.client.return_value
    batch_client.submit_job.return_value = {"jobId": "job-123"}
    overrides = {"environment": [{"name": "ENV", "value": "prod"}]}
    bm.submit_batch_job("my-job-def", "my-job", "my-queue", container_overrides=overrides)
    _, kwargs = batch_client.submit_job.call_args
    assert kwargs["containerOverrides"] == overrides

def test_submit_batch_job_raises_client_error(boto_manager):
    bm, mock_session = boto_manager
    batch_client = mock_session.client.return_value
    batch_client.submit_job.side_effect = ClientError(
        error_response={"Error": {"Code": "ClientException", "Message": "invalid job queue"}},
        operation_name="SubmitJob",
    )
    with pytest.raises(ClientError):
        bm.submit_batch_job("my-job-def", "my-job", "invalid-queue")
