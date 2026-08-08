"""Engine errors that mean analysis is incomplete."""


class ConfigurationError(ValueError):
    """Raised when required policy input is invalid or incomplete."""
