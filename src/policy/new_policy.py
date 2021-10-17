from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Union


def skip_none_dict_factory(obj: Any) -> Dict[str, Any]:
    return {k: v for (k, v) in obj if v is not None}


@dataclass(frozen=True, eq=True)
class NormalizedStatement:
    pass


@dataclass(frozen=True, eq=True)
class Statement:
    def normalize(self) -> NormalizedStatement:
        return NotImplemented


@dataclass(frozen=True, eq=True)
class NormalizedPolicy:
    Statement: List[NormalizedStatement]
    Id: Optional[str] = None
    Version: Optional[str] = None


@dataclass(frozen=True, eq=True)
class Policy:
    Statement: Union[Statement, List[Statement]]
    Id: Optional[str] = None
    Version: Optional[str] = None

    def dict(self) -> Dict[str, Any]:
        return asdict(self, dict_factory=skip_none_dict_factory)

    def normalize(self) -> NormalizedPolicy:
        return NormalizedPolicy(
            Statement=self._normalize_statement(),
            Id=self.Id,
            Version=self.Version,
        )

    def _normalize_statement(self) -> List[NormalizedStatement]:
        if isinstance(self.Statement, list):
            return [statement.normalize() for statement in self.Statement]
        return [self.Statement.normalize()]
