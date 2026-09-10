import pytest
from unittest.mock import patch
from botocore.exceptions import ClientError
from pcdc_aws_client.boto import BotoManager


def test_returns_response_query_completes_on_first_check(boto_manager):
    bm, _ = boto_manager
    logs_client = bm.logs_client
    logs_client.start_query.return_value = {"queryId": "query-123"}
    logs_client.get_query_results.return_value = {"status": "Complete", "results": [["a", "b"]]}
    result = bm.get_logs("my-log-group", 1000, 2000, "fields @message")
    assert result == {"status": "Complete", "results": [["a", "b"]]}
    logs_client.start_query.assert_called_once_with(
        logGroupName="my-log-group",
        startTime=1000,
        endTime=2000,
        queryString="fields @message",
        limit=10000,
    )

def test_polls_until_complete_and_sleeps_between_checks(boto_manager):
    bm, _ = boto_manager
    logs_client = bm.logs_client
    logs_client.start_query.return_value = {"queryId": "query-123"}
    logs_client.get_query_results.side_effect = [
        {"status": "Running"},
        {"status": "Running"},
        {"status": "Complete", "results": []},
    ]

    with patch("time.sleep", return_value=None) as mock_sleep:
        result = bm.get_logs("my-log-group", 1000, 2000, "fields @message")

    assert result == {"status": "Complete", "results": []}
    assert logs_client.get_query_results.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_called_with(60)

def test_client_error_on_start_query_prints_and_returns_none(boto_manager):
    bm, _ = boto_manager
    logs_client = bm.logs_client
    logs_client.start_query.side_effect = ClientError(
        error_response={"Error": {"Code": "ResourceNotFound", "Message": "no such log group"}},
        operation_name="StartQuery",
    )
    result = bm.get_logs("nonexistent-log-group", 1000, 2000, "fields @message")
    assert result is None

def test_error_on_get_query_results_prints_and_returns_none(boto_manager):
    from botocore.exceptions import ClientError
    bm, _ = boto_manager
    logs_client = bm.logs_client
    logs_client.start_query.return_value = {"queryId": "query-123"}
    logs_client.get_query_results.side_effect = ClientError(
        error_response={"Error": {"Code": "Exception", "Message": "rate exceeded"}},
        operation_name="GetQueryResults",
    )
    result = bm.get_logs("my-log-group", 1000, 2000, "fields @message")
    assert result is None

def test_terminal_status_raises_runtime_error(boto_manager):
    bm, _ = boto_manager
    logs_client = bm.logs_client
    logs_client.start_query.return_value = {"queryId": "query-456"}
    logs_client.get_query_results.return_value = {"status": "Failed"}
    with pytest.raises(RuntimeError, match="Failed"):
        bm.get_logs("my-log-group", 1000, 2000, "fields @message")
