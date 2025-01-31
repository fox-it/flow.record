from __future__ import annotations

__path__ = __import__("pkgutil").extend_path(__path__, __name__)  # make this namespace extensible from other packages
import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record


class AbstractWriter(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write(self, rec: Record) -> None:
        """Write a record."""
        raise NotImplementedError

    @abc.abstractmethod
    def flush(self) -> None:
        """Flush any buffered writes."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """Close the Writer, no more writes will be possible."""
        raise NotImplementedError

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> AbstractWriter:  # noqa: PYI034
        return self

    def __exit__(self, *args) -> None:
        self.flush()
        self.close()


class AbstractReader(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __iter__(self) -> Iterator[Record]:
        """Return a record iterator."""
        raise NotImplementedError

    def close(self) -> None:  # noqa: B027
        """Close the Reader, can be overriden to properly free resources."""

    def __enter__(self) -> AbstractReader:  # noqa: PYI034
        return self

    def __exit__(self, *args) -> None:
        self.close()
