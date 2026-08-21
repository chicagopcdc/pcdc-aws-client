import json
import pytest
from unittest.mock import patch, MagicMock
from pcdc_aws_client.boto import BotoManager
from botocore.exceptions import ClientError
from moto import mock_aws
from pcdc_aws_client.errors import InternalError

@pytest.fixture
def boto_manager():
    '''
    builds a botomanager without hitting AWS
    '''
    with mock_aws():
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        bm.s3_client.create_bucket(Bucket="test-bucket")
        bm.s3_client.create_bucket(Bucket="my-new-bucket")
        yield bm

#delete data file
def test_delete_data_file(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="test-keys/keys/apple.tsv", Body=b"a,b,cd")
    msg, status = bm.delete_data_file("test-bucket", "test-keys/keys/")
    assert status == 204
    assert msg == ""
    remaining = bm.s3_client.list_objects_v2(Bucket="test-bucket", Prefix="test-keys/keys/")
    assert remaining.get("Contents") is None

def test_returns_404_file_not_found(boto_manager):
    bm = boto_manager
    msg, status = bm.delete_data_file("test-bucket", "redord/dne")
    assert status == 404
    assert msg == "Unable to delete the data file associated with this record. Backing off."

def test_returns_400_multiple_files(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="test-keys/keys/apple.tsv", Body=b"a,b,cd")
    bm.s3_client.put_object(Bucket="test-bucket", Key="test-keys/keys/pear.tsv", Body=b"a,b,cd")
    msg, status = bm.delete_data_file("test-bucket", "test-keys/keys/")
    assert status == 400
    assert msg == "Multiple files found matching this prefix. Backing off."
    remaining = bm.s3_client.list_objects_v2(Bucket="test-bucket", Prefix="test-keys/keys/")
    assert len(remaining["Contents"]) == 2

def test_nonexistent_bucket_returns_500(boto_manager):
    bm = boto_manager
    msg, status = bm.delete_data_file("bucket-that-does-not-exist", "records/abc123/")
    assert status == 500
    assert msg == "Unable to delete data file."

#copy object between s3
def test_copy_object_between_s3(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"a,b,cd")
    bm.copy_object_between_s3("test-bucket", "my-key", "my-new-bucket")
    copied = bm.s3_client.get_object(Bucket="my-new-bucket", Key="my-key")
    assert copied["Body"].read() == b"a,b,cd"

def test_copy_object_config_with_access_key_works(boto_manager):
    bm = boto_manager
    config = {"aws_access_key_id": "KSHSSA", "aws_secret_access_key": "lakhjsl34ksj"}   
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"a,b,cd")
    bm.copy_object_between_s3("test-bucket", "my-key", "my-new-bucket", config=config)
    copied = bm.s3_client.get_object(Bucket="my-new-bucket", Key="my-key")
    assert copied["Body"].read() == b"a,b,cd"
    

def test_copy_object_between_s3_with_destination_key(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"a,b,cd")
    bm.copy_object_between_s3("test-bucket", "my-key", "my-new-bucket", dest_key="abracadabra-key")
    copied = bm.s3_client.get_object(Bucket="my-new-bucket", Key="abracadabra-key")
    assert copied["Body"].read() == b"a,b,cd"

    with pytest.raises(ClientError):
        bm.s3_client.get_object(Bucket="dest-bucket", Key="my-key")

def test_copy_object_between_s3_raise_exception_nonexistent_source_key(boto_manager):
    bm = boto_manager
    with pytest.raises(ClientError):
        bm.copy_object_between_s3("test-bucket", "my-failed-key", "my-new-bucket")

def test_copy_object_between_s3_raise_exception_nonexistent_source_bucket(boto_manager):
    bm = boto_manager
    with pytest.raises(ClientError):
        bm.copy_object_between_s3("failed-bucket", "my-key", "my-new-bucket")

def test_copy_object_between_s3_raise_exception_nonexistent_dest_bucket(boto_manager):
    bm = boto_manager
    with pytest.raises(ClientError):
        bm.copy_object_between_s3("test-bucket", "my-key", "my-failed-new-bucket")

#assert keys exist
def test_assert_keys_exist(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"a,b,cd")
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key2", Body=b"a,b,cd")
    result = bm.assert_keys_exist("test-bucket", ["my-key", "my-key2"])
    assert result is None

def test_raises_when_a_key_is_missing(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"x")
    with pytest.raises(ClientError):
        bm.assert_keys_exist("test-bucket", ["my-key", "my-key2"])

def test_empty_keys_list_does_nothing(boto_manager):
    bm = boto_manager
    result = bm.assert_keys_exist("test-bucket", [])
    assert result is None

def test_assert_keys_config_with_access_key_correct(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"x")
    config = {"aws_access_key_id": "AKIA...", "aws_secret_access_key": "secret"}
    result = bm.assert_keys_exist("test-bucket", ["my-key"], config=config)
    assert result is None

# delete s3
def test_delete_s3_objects(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"x")
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key2", Body=b"x")
    bm.delete_s3_objects("test-bucket", ["my-key", "my-key2"])
    remaining = bm.s3_client.list_objects_v2(Bucket="test-bucket")
    assert remaining.get("Contents") is None

def test_partial_existence_deletes_the_ones_that_exist(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="my-key", Body=b"x")
    bm.delete_s3_objects("test-bucket", ["my-key", "failed-key"])
    remaining = bm.s3_client.list_objects_v2(Bucket="test-bucket")
    assert remaining.get("Contents") is None

def test_delete_s3_objects_raises_and_logs_when_bucket_does_not_exist(boto_manager):
    bm = boto_manager
    with pytest.raises(Exception):
        bm.delete_s3_objects("failed-bucket", ["my-key"])
    bm.logger.error.assert_called_once()

#load csv from s3
def test_loads_rows_as_list_of_dicts(boto_manager):
    bm = boto_manager
    csv_content = "user_id,timestamp,raw\n1,100,foo\n2,200,bar\n"
    bm.s3_client.put_object(Bucket="test-bucket", Key="cache/cache.csv", Body=csv_content.encode("utf-8"))

    result = bm.load_csv_from_s3("test-bucket")

    assert result == [
        {"user_id": "1", "timestamp": "100", "raw": "foo"},
        {"user_id": "2", "timestamp": "200", "raw": "bar"},
    ]


def test_returns_empty_when_no_file_exists(boto_manager):
    bm = boto_manager
    result = bm.load_csv_from_s3("test-bucket")
    assert result == []


def test_load_csv_uses_custom_key_when_given(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(
        Bucket="test-bucket", Key="custom/path.csv", Body=b"a,b\n1,2\n"
    )

    result = bm.load_csv_from_s3("test-bucket", s3_key="custom/path.csv")

    assert result == [{"a": "1", "b": "2"}]

#upload_csv_content_to_s3
def test_uploads_rows_as_csv(boto_manager):
    bm = boto_manager
    rows = [{"user_id": "1", "timestamp": "100", "raw": "foo"}]
    bm.upload_csv_content_to_s3(rows, "test-bucket")
    obj = bm.s3_client.get_object(Bucket="test-bucket", Key="cache/cache.csv")
    content = obj["Body"].read().decode("utf-8")
    assert content == "user_id,timestamp,raw\r\n1,100,foo\r\n"

def test_upload_csv_uses_custom_key_when_given(boto_manager):
    bm = boto_manager
    rows = [{"a": "1"}]
    bm.upload_csv_content_to_s3(rows, "test-bucket", s3_key="custom/out.csv")
    obj = bm.s3_client.get_object(Bucket="test-bucket", Key="custom/out.csv")
    assert obj["Body"].read().decode("utf-8") == "a\r\n1\r\n"

def test_compatible_with_load_csv_from_s3(boto_manager):
    bm = boto_manager
    rows = [{"user_id": "1", "timestamp": "100", "raw": "foo"}]

    bm.upload_csv_content_to_s3(rows, "test-bucket")
    result = bm.load_csv_from_s3("test-bucket")

    assert result == rows

#get json from s3
def test_returns_parsed_json(boto_manager):
    bm = boto_manager
    data = {"foo": "bar", "count": 3}
    bm.s3_client.put_object(Bucket="test-bucket", Key="config.json", Body=json.dumps(data).encode("utf-8"))
    result = bm.get_json_from_s3("test-bucket", "config.json")
    assert result == data

def test_returns_none_when_key_does_not_exist(boto_manager):
    bm = boto_manager
    result = bm.get_json_from_s3("test-bucket", "does-not-exist.json")
    assert result is None
    bm.logger.warning.assert_called_once()

def test_raises_and_logs_on_error(boto_manager):
    bm = boto_manager
    with pytest.raises(Exception):
        bm.get_json_from_s3("bucket-that-does-not-exist", "config.json")
    bm.logger.error.assert_called_once()

def test_raises_on_malformed_json(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="bad.json", Body=b"{not valid json")

    with pytest.raises(json.JSONDecodeError):
        bm.get_json_from_s3("test-bucket", "bad.json")

#put json to s3
def test_writes_json(boto_manager):
    bm = boto_manager
    data = {"foo": "bar", "nested": {"x": 1}}
    bm.put_json_to_s3("test-bucket", "config.json", data)
    obj = bm.s3_client.get_object(Bucket="test-bucket", Key="config.json")
    content = obj["Body"].read().decode("utf-8")
    assert json.loads(content) == data

def test_overwrites_existing_key(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="config.json", Body=b'{"old": true}')
    bm.put_json_to_s3("test-bucket", "config.json", {"new": True})
    obj = bm.s3_client.get_object(Bucket="test-bucket", Key="config.json")
    assert json.loads(obj["Body"].read()) == {"new": True}

def test_put_json_raises_and_logs_when_bucket_does_not_exist(boto_manager):
    bm = boto_manager
    with pytest.raises(Exception):
        bm.put_json_to_s3("bucket-that-does-not-exist", "config.json", {"a": 1})
    bm.logger.error.assert_called_once()

def test_compatible_with_get_json_from_s3(boto_manager):
    bm = boto_manager
    data = {"a": [1, 2, 3], "b": "text"}
    bm.put_json_to_s3("test-bucket", "config.json", data)
    result = bm.get_json_from_s3("test-bucket", "config.json")
    assert result == data

#get list files in s3
def test_lists_all_keys_under_prefix(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="folder/a.tsv", Body=b"x")
    bm.s3_client.put_object(Bucket="test-bucket", Key="folder/b.tsv", Body=b"y")
    bm.s3_client.put_object(Bucket="test-bucket", Key="other/c.tsv", Body=b"z")
    result = bm.get_list_files_in_s3_folder("test-bucket", "folder/")
    assert sorted(result) == ["folder/a.tsv", "folder/b.tsv"]

def test_returns_empty_list_when_prefix_has_no_matches(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="folder/a.tsv", Body=b"x")
    result = bm.get_list_files_in_s3_folder("test-bucket", "no-match/")
    assert result == []

def test_includes_nested_keys(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="folder/nested/file.tsv", Body=b"x")
    result = bm.get_list_files_in_s3_folder("test-bucket", "folder/")
    assert "folder/nested/file.tsv" in result

def test_uri_type_argument_has_no_effect_on_output(boto_manager):
    bm = boto_manager
    bm.s3_client.put_object(Bucket="test-bucket", Key="folder/a.tsv", Body=b"x")
    result_default = bm.get_list_files_in_s3_folder("test-bucket", "folder/")
    result_custom = bm.get_list_files_in_s3_folder("test-bucket", "folder/", uri_type="s3n")
    assert result_default == result_custom == ["folder/a.tsv"]

#multipart upload
def test_multipart_upload(boto_manager):
    bm = boto_manager
    key = "large-file.tsv"
    upload_id = bm.initilize_multipart_upload("test-bucket", key, MAX_TRIES=3)
    assert upload_id
    part_body = b"x" * (5 * 1024 * 1024)
    part_response = bm.s3_client.upload_part(
        Bucket="test-bucket", Key=key, PartNumber=1, UploadId=upload_id, Body=part_body
    )
    parts = [{"ETag": part_response["ETag"], "PartNumber": 1}]
    bm.complete_multipart_upload("test-bucket", key, upload_id, parts, MAX_TRIES=3)
    result = bm.s3_client.get_object(Bucket="test-bucket", Key=key)
    assert result["Body"].read() == part_body

def test_complete_multipart_upload_raises_on_mismatched_parts(boto_manager):
    bm = boto_manager
    key = "large-file.tsv"
    upload_id = bm.initilize_multipart_upload("test-bucket", key, MAX_TRIES=3)
    bad_parts = [{"ETag": '"nonexistent-etag"', "PartNumber": 99}]
    with pytest.raises(InternalError):
        bm.complete_multipart_upload("test-bucket", key, upload_id, bad_parts, MAX_TRIES=1)