from typing import Dict, List, Literal, Union

from pydantic.types import StrictBool, StrictFloat, StrictInt, StrictStr


StrOrListStr = Union[StrictStr, List[StrictStr]]

Effect = Literal["Allow", "Deny"]

Version = Literal["2008-10-17", "2012-10-17"]

Star = Literal["*"]

ConditionOperator = Literal[
    "StringEquals",
    "StringEqualsIfExists",
    "StringNotEquals",
    "StringNotEqualsIfExists",
    "StringEqualsIgnoreCase",
    "StringEqualsIgnoreCaseIfExists",
    "StringNotEqualsIgnoreCase",
    "StringNotEqualsIgnoreCaseIfExists",
    "StringLike",
    "StringLikeIfExists",
    "StringNotLike",
    "StringNotLikeIfExists",
    "NumericEquals",
    "NumericEqualsIfExists",
    "NumericNotEquals",
    "NumericNotEqualsIfExists",
    "NumericLessThan",
    "NumericLessThanIfExists",
    "NumericLessThanEquals",
    "NumericLessThanEqualsIfExists",
    "NumericGreaterThan",
    "NumericGreaterThanIfExists",
    "NumericGreaterThanEquals",
    "NumericGreaterThanEqualsIfExists",
    "DateEquals",
    "DateEqualsIfExists",
    "DateNotEquals",
    "DateNotEqualsIfExists",
    "DateLessThan",
    "DateLessThanIfExists",
    "DateLessThanEquals",
    "DateLessThanEqualsIfExists",
    "DateGreaterThan",
    "DateGreaterThanIfExists",
    "DateGreaterThanEquals",
    "DateGreaterThanEqualsIfExists",
    "Bool",
    "BoolIfExists",
    "BinaryEquals",
    "BinaryEqualsIfExists",
    "IpAddress",
    "IpAddressIfExists",
    "NotIpAddress",
    "NotIpAddressIfExists",
    "ArnEquals",
    "ArnEqualsIfExists",
    "ArnLike",
    "ArnLikeIfExists",
    "ArnNotEquals",
    "ArnNotEqualsIfExists",
    "ArnNotLike",
    "ArnNotLikeIfExists",
    "Null",
]

ConditionValue = Union[StrictStr, StrictInt, StrictFloat, StrictBool]

Condition = Dict[StrictStr, Dict[StrictStr, Union[ConditionValue, List[ConditionValue]]]]

NormalizedCondition = Dict[StrictStr, Dict[StrictStr, Union[StrictStr, List[StrictStr]]]]

StrictStrList = List[StrictStr]
