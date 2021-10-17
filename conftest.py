from typing import Any, Dict
import pytest


@pytest.fixture
def policy() -> Dict[str, Any]:
    return {
        "Id": "test_id",
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "test_sid",
                "Action": "s3:*",
                "Effect": "Deny",
                "Resource": ["arn:aws:s3:::test-bucket", "arn:aws:s3:::test-bucket/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                "Principal": "*",
            },
        ],
    }
