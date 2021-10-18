import pytest
from pydantic.error_wrappers import ValidationError

from policy.policy import Policy, Statement


@pytest.mark.parametrize("version", ["2008-10-17", "2012-10-17"])
def test_policy_parses_valid_version(version):
    policy = {"Version": version, "Statement": []}
    result = Policy(**policy)
    assert result.Version == version
    assert result.dict()["Version"] == version


@pytest.mark.parametrize("version", ["1234-56-78", 12, [], (), {}])
def test_policy_fails_on_invalid_version(version):
    policy = {"Version": version, "Statement": []}
    with pytest.raises(ValidationError) as error:
        Policy(**policy)
    assert "Version" in str(error)


@pytest.mark.parametrize("id", ["test_id", "test another id"])
def test_policy_parses_valid_id(id):
    policy = {"Id": id, "Statement": []}
    result = Policy(**policy)
    assert result.Id == id
    assert result.dict()["Id"] == id


@pytest.mark.parametrize("id", [int(12), [], (), {}])
def test_policy_parses_invalid_id(id):
    policy = {"Id": id, "Statement": [{"Action": "*", "Effect": "Allow", "Resource": "*"}]}
    with pytest.raises(ValidationError) as error:
        Policy(**policy)
    assert "Id" in str(error)


def test_policy_expects_a_statement():
    policy = {}
    with pytest.raises(ValidationError) as error:
        Policy(**policy)
    assert "Statement" in str(error)


def test_policy_parses_minimal_valid_statement():
    policy = {"Statement": [{"Action": "*", "Effect": "Allow", "Resource": "*"}]}
    result = Policy(**policy)
    assert result.dict()["Statement"] == policy["Statement"]


def test_statement_requires_effect():
    statement = {"Action": [], "Resource": [{"Action": "*", "Effect": "Allow", "Resource": "*"}]}
    with pytest.raises(ValidationError) as error:
        Statement(**statement)
    assert "Effect" in str(error)


def test_statement_validates_effect():
    statement = {"Action": [], "Resource": [], "Effect": "wrong"}
    with pytest.raises(ValidationError) as error:
        Statement(**statement)
    assert "Effect" in str(error)


def test_statement_parses_effect():
    statement = {"Action": [], "Resource": [], "Effect": "Allow"}
    result = Statement(**statement)
    assert result.Effect == "Allow"


def test_parse_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MustBeEncryptedInTransit",
                "Action": "s3:*",
                "Effect": "Deny",
                "Resource": ["arn:aws:s3:::scranton-bucket", "arn:aws:s3:::scranton-bucket/*"],
                "Condition": {"Bool": {"aws:SecureTransport": [False]}},
                "Principal": {"AWS": ["*"]},
            }
        ],
    }
    result = Policy(**policy)
    assert result.dict() == policy


@pytest.mark.parametrize(
    "original,expected",
    [
        (
            {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["*"]}},
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:putobject"], "Resource": ["*"]}],
            },
        ),
        (
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "MustBeEncryptedInTransit",
                        "Action": "s3:*",
                        "Effect": "Deny",
                        "Resource": ["arn:aws:s3:::scranton-bucket", "arn:aws:s3:::scranton-bucket/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        "Principal": "*",
                    }
                ],
            },
            {
                "Statement": [
                    {
                        "Action": ["s3:*"],
                        "Condition": {"Bool": {"aws:securetransport": "false"}},
                        "Effect": "Deny",
                        "Principal": {"AWS": ["*"]},
                        "Resource": ["arn:aws:s3:::scranton-bucket", "arn:aws:s3:::scranton-bucket/*"],
                        "Sid": "MustBeEncryptedInTransit",
                    }
                ],
                "Version": "2012-10-17",
            },
        ),
        (
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:putobject", "Resource": ["*"]}]},
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:putobject"], "Resource": ["*"]}],
            },
        ),
        (
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": ["s3:List*", "s3:GetObject*", "s3:PutObject", "ec2:DESCRIBE*", "ec2:list*"],
                        "Resource": "*",
                    }
                ],
            },
            {
                "Statement": [
                    {
                        "Action": ["ec2:describe*", "ec2:list*", "s3:getobject*", "s3:list*", "s3:putobject"],
                        "Effect": "Allow",
                        "Resource": ["*"],
                        "Sid": "VisualEditor0",
                    }
                ],
                "Version": "2012-10-17",
            },
        ),
        (
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:putobject",
                        "Principal": {"Service": "cloudtrail.amazonaws.com", "AWS": "arn:aws:iam::012345678901:root"},
                        "Resource": ["*"],
                    }
                ],
            },
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:putobject"],
                        "Principal": {
                            "AWS": ["arn:aws:iam::012345678901:root"],
                            "Service": ["cloudtrail.amazonaws.com"],
                        },
                        "Resource": ["*"],
                    }
                ],
            },
        ),
        (
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:putobject"], "Principal": "*", "Resource": ["*"]}],
            },
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:putobject"], "Principal": {"AWS": ["*"]}, "Resource": ["*"]}
                ],
            },
        ),
        (
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:putobject", "Resource": "*"}]},
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:putobject"], "Resource": ["*"]}],
            },
        ),
        (
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:putobject",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"AWS:Username": [True, 20.15]}},
                    }
                ],
            },
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:putobject"],
                        "Resource": ["*"],
                        "Condition": {"StringEquals": {"aws:username": ["true", "20.15"]}},
                    }
                ],
            },
        ),
    ],
)
def test_normalize_policy(original, expected):
    assert Policy(**original).normalize().dict() == expected
