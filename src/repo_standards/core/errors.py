from typing import Never


class ConfigurationError(ValueError):
    @classmethod
    def fail(cls, message: str) -> Never:
        raise cls(message)


class ManifestAbsentError(ConfigurationError):
    pass


class BaselineError(ConfigurationError):
    """A selected baseline input or comparison could not be accepted."""
