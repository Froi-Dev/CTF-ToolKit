from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

InputT = TypeVar("InputT")
ResultT = TypeVar("ResultT")


class BaseAnalyzer(ABC, Generic[InputT, ResultT]):
    """Small common contract used by all CTFKit analyzers."""

    name: str
    category: str

    @abstractmethod
    def supports(self, value: object) -> bool:
        """Return whether this analyzer can safely process the value."""

    @abstractmethod
    def analyze(self, value: InputT) -> ResultT:
        """Return a result without mutating persistence or UI state."""

