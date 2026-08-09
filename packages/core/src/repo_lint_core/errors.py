"""Engine errors that mean analysis is incomplete."""

from typing import Never


class ConfigurationError(ValueError):
    """Raised when required policy input is invalid or incomplete."""

    @classmethod
    def fail(cls, message: str) -> Never:
        """Raise one invalid-input error without inline exception construction."""
        raise cls(message)
