import json
from typing import List, Optional, Union

from pydantic.types import StrictStr

from policy.model import PolicyModel, StatementModel
from policy.types import (
    Condition,
    ConditionValue,
    Effect,
    NormalizedCondition,
    Star,
    StrictStrList,
    StrOrListStr,
    Version,
)


def _to_list_of_strings(raw: Optional[StrOrListStr], to_lower: bool = False) -> Optional[StrictStrList]:
    if raw is None:
        return None
    elif isinstance(raw, str):
        return [raw.lower() if to_lower else raw]
    return sorted([item.lower() for item in raw] if to_lower else raw)


def _normalize_condition_value(val: Union[ConditionValue, List[ConditionValue]]) -> List[str]:
    if isinstance(val, list):
        return [v if isinstance(v, str) else json.dumps(v) for v in val]
    return [val if isinstance(val, str) else json.dumps(val)]


class NormalizedPrincipal(PolicyModel):
    AWS: Optional[StrictStrList]
    Federated: Optional[StrictStrList]
    Service: Optional[StrictStrList]
    CanonicalUser: Optional[StrictStrList]


class Principal(PolicyModel):
    AWS: Optional[StrOrListStr]
    Federated: Optional[StrOrListStr]
    Service: Optional[StrOrListStr]
    CanonicalUser: Optional[StrOrListStr]

    def normalize(self) -> NormalizedPrincipal:
        return NormalizedPrincipal(
            AWS=_to_list_of_strings(self.AWS),
            Federated=_to_list_of_strings(self.Federated),
            Service=_to_list_of_strings(self.Service),
            CanonicalUser=_to_list_of_strings(self.CanonicalUser),
        )


class NormalizedStatement(StatementModel):
    Action: Optional[StrictStrList]
    Condition: Optional[NormalizedCondition]
    Effect: Effect
    NotAction: Optional[StrictStrList]
    NotResource: Optional[StrictStrList]
    Principal: Optional[NormalizedPrincipal]
    Resource: Optional[StrictStrList]
    Sid: Optional[StrictStr]


class Statement(StatementModel):
    Action: Optional[StrOrListStr]
    Condition: Optional[Condition]
    Effect: Effect
    NotAction: Optional[StrOrListStr]
    NotResource: Optional[StrOrListStr]
    Principal: Optional[Union[Star, Principal]]
    Resource: Optional[StrOrListStr]
    Sid: Optional[StrictStr]

    def normalize(self) -> NormalizedStatement:
        return NormalizedStatement(
            Action=_to_list_of_strings(self.Action, to_lower=True),
            Condition=self._normalize_condition(),
            Effect=self.Effect,
            NotAction=_to_list_of_strings(self.NotAction),
            NotResource=_to_list_of_strings(self.NotResource),
            Principal=self._normalize_principal(),
            Resource=_to_list_of_strings(self.Resource),
            Sid=self.Sid,
        )

    def _normalize_principal(self) -> Optional[NormalizedPrincipal]:
        if self.Principal is None:
            return None
        elif self.Principal == "*":
            return NormalizedPrincipal(AWS=["*"])
        else:
            return self.Principal.normalize()

    def _normalize_condition(self) -> Optional[NormalizedCondition]:
        if self.Condition is None:
            return self.Condition
        return {
            condition_type_string: {
                condition_key_string.lower(): _normalize_condition_value(condition_values)
                for condition_key_string, condition_values in condition_dict.items()
            }
            for condition_type_string, condition_dict in self.Condition.items()
        }


class NormalizedPolicy(PolicyModel):
    Id: Optional[StrictStr]
    Statement: List[NormalizedStatement]
    Version: Optional[Version]


class Policy(PolicyModel):
    Id: Optional[StrictStr]
    Statement: Union[Statement, List[Statement]]
    Version: Optional[Version]

    def normalize(self) -> NormalizedPolicy:
        return NormalizedPolicy(
            Id=self.Id,
            Statement=self._normalize_statement(),
            Version=self.Version,
        )

    def _normalize_statement(self) -> List[NormalizedStatement]:
        if isinstance(self.Statement, list):
            return [statement.normalize() for statement in self.Statement]
        return [self.Statement.normalize()]
