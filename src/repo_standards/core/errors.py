from typing import Never


class ConfigurationError(ValueError):
    @classmethod
    def fail(cls, message: str) -> Never:
        raise cls(message)
