import pytest
from unittest.mock import patch, MagicMock
from pcdc_aws_client.boto import BotoManager
from botocore.exceptions import ClientError
from moto import mock_aws

@pytest.fixture
def boto_manager():
    '''
    builds a botomanager without hitting AWS
    '''
    with mock_aws():
        bm = BotoManager(config={"region_name": "us-east-1"}, logger=MagicMock())
        bm.s3_client.create_bucket(Bucket="test-bucket")
        yield bm

#get user group
def test_get_user_group(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    bm.iam.create_group(GroupName="group2")
    res = bm.get_user_group(["group1", "group2"])
    assert set(res.keys()) == {"group1", "group2"}

def test_get_user_group_returns_empty_dict_when_none_exist(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    result = bm.get_user_group(["nonexistent1", "nonexistent2"])
    assert result == {}

def test_get_user_group_extra_groups(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    bm.iam.create_group(GroupName="group2")
    bm.iam.create_group(GroupName="extra-group")
    res = bm.get_user_group(["group1", "group2"])
    assert set(res.keys()) == {"group1", "group2"}

#get all groups
def test_get_all_groups(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    bm.iam.create_group(GroupName="group2")
    bm.iam.create_group(GroupName="group3")
    res = bm.get_all_groups(["group1", "group2", "group3"])
    assert set(res.keys()) == {"group1", "group2", "group3"}
'''
Uncomment this test when __get_policy_document_by_group_name__ is no longer a stub. 
Currently get_all_groups cannot add a group as create_user_group does not work

def test_get_all_groups_add(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    bm.iam.create_group(GroupName="group2")
    res = bm.get_all_groups(["group1", "group2", "extra_group"])
    assert set(res.keys()) == {"group1", "group2", "extra_group"}
'''

#add user to group
def test_add_user_to_group(boto_manager):
    bm = boto_manager
    bm.iam.create_user(UserName="anthony")
    bm.iam.create_group(GroupName="group1")
    bm.iam.create_group(GroupName="group2")
    groups = bm.get_user_group(["group1", "group2"])
    bm.add_user_to_group(groups, "anthony")
    member_of = bm.iam.list_groups_for_user(UserName="anthony")["Groups"]
    mem_names = {g["GroupName"] for g in member_of}
    assert mem_names == {"group1", "group2"}

def test_add_user_to_group_raises_when_user_does_not_exist(boto_manager):
    bm = boto_manager
    bm.iam.create_group(GroupName="group1")
    groups = bm.get_user_group(["group1"])
    with pytest.raises(Exception):
        bm.add_user_to_group(groups, "user-does-not-exist")


def test_add_user_to_group_with_empty_groups_does_nothing(boto_manager):
    bm = boto_manager
    bm.iam.create_user(UserName="alice")
    result = bm.add_user_to_group({}, "alice")
    assert result is None
    memberships = bm.iam.list_groups_for_user(UserName="alice")["Groups"]
    assert memberships == []


def test_add_user_to_group_raises_when_group_does_not_actually_exist(boto_manager):
    bm = boto_manager
    bm.iam.create_user(UserName="alice")
    fake_groups = {"ghost-group": {"GroupName": "ghost-group"}}
    with pytest.raises(Exception):
        bm.add_user_to_group(fake_groups, "alice")