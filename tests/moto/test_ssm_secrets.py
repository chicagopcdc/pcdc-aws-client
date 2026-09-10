import json
import pytest
from botocore.exceptions import ClientError


#get secret
def test_get_secret_returns_raw_secret_string(boto_manager):
    bm = boto_manager
    bm.secrets_client.create_secret(Name="db-password", SecretString="hunter2")
    result = bm.get_secret("db-password")
    assert result == "hunter2"

def test_get_secret_returns_raw_json_string_unparsed(boto_manager):
    bm = boto_manager
    raw_json = json.dumps({"username": "admin", "password": "hunter2"})
    bm.secrets_client.create_secret(Name="db-creds", SecretString=raw_json)
    result = bm.get_secret("db-creds")
    assert isinstance(result, str)
    assert result == raw_json
    assert json.loads(result) == {"username": "admin", "password": "hunter2"}

def test_get_secret_raises_when_secret_does_not_exist(boto_manager):
    bm = boto_manager
    with pytest.raises(ClientError):
        bm.get_secret("nonexistent-secret")

#get_param_from_ssm
def test_get_param_from_ssm_returns_parsed_json(boto_manager):
    bm = boto_manager
    data = {"api_key": "abc123", "region": "us-east-1"}
    bm.ssm_client.put_parameter(
        Name="/app/config", Value=json.dumps(data), Type="SecureString"
    )

    result = bm.get_param_from_ssm("/app/config")
    assert result == data

def test_get_param_from_ssm_raises_on_non_json_value(boto_manager):
    bm = boto_manager
    bm.ssm_client.put_parameter(Name="/app/plain-value", Value="just-a-string", Type="String")
    with pytest.raises(json.JSONDecodeError):
        bm.get_param_from_ssm("/app/plain-value")

def test_get_param_from_ssm_raises_when_parameter_does_not_exist(boto_manager):
    bm = boto_manager
    with pytest.raises(ClientError):
        bm.get_param_from_ssm("/app/does-not-exist")

def test_get_param_from_ssm_requests_decryption(boto_manager):
    from unittest.mock import patch
    bm = boto_manager
    bm.ssm_client.put_parameter(
        Name="/app/secure", Value=json.dumps({"x": 1}), Type="SecureString"
    )
    with patch.object(bm.ssm_client, "get_parameter", wraps=bm.ssm_client.get_parameter) as spy:
        bm.get_param_from_ssm("/app/secure")
        spy.assert_called_once_with(Name="/app/secure", WithDecryption=True)