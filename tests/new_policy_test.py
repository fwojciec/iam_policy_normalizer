import pytest

from policy.new_policy import Policy


@pytest.mark.parametrize("version", ["2008-10-17", "2012-10-17"])
def test_policy_parses_valid_version(version):
    policy = {"Version": version, "Statement": []}
    result = Policy(**policy)
    assert result.Version == version
    assert result.dict() == policy
