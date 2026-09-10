import pytest

#get vpc gateway ips
def test_get_vpc_nat_gateway_ips(boto_manager):
    bm = boto_manager
    vpc = bm.ec2_client.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "my-vpc"}]}
        ],
    )["Vpc"]
    subnet = bm.ec2_client.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    eip = bm.ec2_client.allocate_address(Domain="vpc")
    bm.ec2_client.create_nat_gateway(SubnetId=subnet["SubnetId"], AllocationId=eip["AllocationId"])
    ips = bm.get_vpc_nat_gateway_ips("my-vpc")
 
    assert len(ips) == 1
    assert ips[0].endswith("/32")

def test_returns_empty_list_when_vpc_not_found(boto_manager):
    bm = boto_manager
    assert bm.get_vpc_nat_gateway_ips("nonexistent-vpc") == []

def test_returns_empty_list_when_vpc_exists_but_has_no_nat_gateways(boto_manager):
    bm = boto_manager
    bm.ec2_client.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "my-vpc"}]}
        ],
    )
 
    assert bm.get_vpc_nat_gateway_ips("my-vpc") == []

#get ec2 ips
def test_get_ec2_public_ips_by_name(boto_manager):
    bm = boto_manager
    vpc = bm.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = bm.ec2_client.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24"
    )["Subnet"]
    bm.ec2_client.modify_subnet_attribute(
        SubnetId=subnet["SubnetId"], MapPublicIpOnLaunch={"Value": True}
    )
    bm.ec2_client.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
        SubnetId=subnet["SubnetId"],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-server"}]}
        ],
    )
 
    ips = bm.get_ec2_public_ips_by_name("web-server")
 
    assert len(ips) == 1
    assert ips[0].endswith("/32")

def test_get_ec2_public_ips_returns_empty_list_when_no_match(boto_manager):
    bm = boto_manager
    assert bm.get_ec2_public_ips_by_name("web-server") == []

def test_get_ec2_public_ips_excludes_instances_without_matching_name(boto_manager):
    bm = boto_manager
    vpc = bm.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    subnet = bm.ec2_client.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
    bm.ec2_client.modify_subnet_attribute(
        SubnetId=subnet["SubnetId"], MapPublicIpOnLaunch={"Value": True}
    )
    bm.ec2_client.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
        SubnetId=subnet["SubnetId"],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "database-01"}]}
        ],
    )
    assert bm.get_ec2_public_ips_by_name("web-server") == []

#restrict sc
def _create_security_group(bm):
    vpc = bm.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = bm.ec2_client.create_security_group(
        GroupName="test-sg", Description="test", VpcId=vpc["VpcId"]
    )
    return sg["GroupId"]
 
def _get_ip_ranges_for_sg(bm, sg_id):
    """Flatten current ingress rules into {cidr: {(protocol, port), ...}}."""
    response = bm.ec2_client.describe_security_groups(GroupIds=[sg_id])
    result = {}
    for sc in response["SecurityGroups"]:
        for perm in sc["IpPermissions"]:
            for ip_range in perm["IpRanges"]:
                result.setdefault(ip_range["CidrIp"], set()).add(
                    (perm["IpProtocol"], perm.get("FromPort"), perm.get("ToPort"))
                )
    return result

def test_restrict_sc_removes_open_http_and_https_access(boto_manager):
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    bm.restrict_sc(sg_id, [])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert "0.0.0.0/0" not in rules
 
def test_restrict_sc_leaves_non_http_open_rules_untouched(boto_manager):
    """Only tcp/80 and tcp/443 on 0.0.0.0/0 get revoked -- other protocols
    or ports on the open CIDR are left alone."""
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    bm.restrict_sc(sg_id, [])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert ("tcp", 22, 22) in rules.get("0.0.0.0/0", set())
 
def test_restrict_sc_adds_80_and_443_for_new_ip(boto_manager):
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.restrict_sc(sg_id, ["203.0.113.5/32"])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert rules["203.0.113.5/32"] == {("tcp", 80, 80), ("tcp", 443, 443)}
 
def test_restrict_sc_does_not_duplicate_existing_rule(boto_manager):
    """If an IP already has both 80 and 443, restrict_sc should not
    attempt to re-add them (which would raise InvalidPermission.Duplicate)."""
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "203.0.113.5/32"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "203.0.113.5/32"}]},
        ],
    )
    bm.restrict_sc(sg_id, ["203.0.113.5/32"])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert rules["203.0.113.5/32"] == {("tcp", 80, 80), ("tcp", 443, 443)}
 
def test_restrict_sc_adds_only_missing_port_when_ip_partially_present(boto_manager):
    """IP already has port 80 but not 443 -- only 443 should be added."""
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "203.0.113.5/32"}]},
        ],
    )
    bm.restrict_sc(sg_id, ["203.0.113.5/32"])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert rules["203.0.113.5/32"] == {("tcp", 80, 80), ("tcp", 443, 443)}
 
def test_restrict_sc_full_scenario_open_access_replaced_by_allowlist(boto_manager):
    """End-to-end: starts fully open, ends restricted to exactly the
    allowlisted IPs on 80/443."""
    bm = boto_manager
    sg_id = _create_security_group(bm)
    bm.ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    bm.restrict_sc(sg_id, ["203.0.113.5/32", "198.51.100.10/32"])
    rules = _get_ip_ranges_for_sg(bm, sg_id)
    assert "0.0.0.0/0" not in rules
    assert rules["203.0.113.5/32"] == {("tcp", 80, 80), ("tcp", 443, 443)}
    assert rules["198.51.100.10/32"] == {("tcp", 80, 80), ("tcp", 443, 443)}