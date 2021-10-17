from typing import AbstractSet, Any, Callable, Dict, Mapping, Optional, Union
from pydantic.class_validators import root_validator

from pydantic.main import BaseModel


def validate_either_or(value1, value2, msg):
    if (value1 is None and value2 is None) or (value1 is not None and value2 is not None):
        raise ValueError(msg)


class PolicyModel(BaseModel):
    def dict(
        self,
        *,
        include: Union[AbstractSet[Union[int, str]], Mapping[Union[int, str], Any]] = None,
        exclude: Union[AbstractSet[Union[int, str]], Mapping[Union[int, str], Any]] = None,
        by_alias: bool = False,
        skip_defaults: bool = None,
        exclude_unset: bool = True,
        exclude_defaults: bool = False,
        exclude_none: bool = True
    ) -> Dict[str, Any]:
        return super().dict(
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            skip_defaults=skip_defaults,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
        )

    def json(
        self,
        *,
        include: Union[AbstractSet[Union[int, str]], Mapping[Union[int, str], Any]] = None,
        exclude: Union[AbstractSet[Union[int, str]], Mapping[Union[int, str], Any]] = None,
        by_alias: bool = False,
        skip_defaults: bool = None,
        exclude_unset: bool = True,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        encoder: Optional[Callable[[Any], Any]] = None,
        **dumps_kwargs: Any
    ) -> str:
        return super().json(
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            skip_defaults=skip_defaults,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            encoder=encoder,
            **dumps_kwargs
        )


class StatementModel(PolicyModel):
    @root_validator()
    def either_action_or_not_action(cls, values):
        validate_either_or(
            values.get("Action"),
            values.get("NotAction"),
            "either 'Action' or 'NotAction' is required",
        )
        return values

    @root_validator()
    def either_resource_or_not_resource(cls, values):
        validate_either_or(
            values.get("Resource"),
            values.get("NotResource"),
            "either 'Resource' or 'NotResource' is required",
        )
        return values
