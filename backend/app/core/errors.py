class DecoderInputError(ValueError):
    """Raised when decoder-specific request options are invalid."""


class ArtifactTooLargeError(ValueError):
    """Raised when an upload crosses the configured artifact-size boundary."""

    def __init__(self, maximum_bytes: int) -> None:
        self.maximum_bytes = maximum_bytes
        super().__init__(f"Artifact exceeds the {maximum_bytes}-byte upload limit.")


class InvalidArtifactError(ValueError):
    """Raised when an uploaded artifact cannot be handled safely."""


class ToolNotAvailableError(RuntimeError):
    """Raised when an allowlisted external analysis tool is unavailable."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(f"{tool} is not installed or is not available on PATH.")


class ToolExecutionError(RuntimeError):
    """Raised when an external analysis tool fails safely."""

    def __init__(self, tool: str, message: str, *, timed_out: bool = False) -> None:
        self.tool = tool
        self.timed_out = timed_out
        super().__init__(message)


class UnsafeWebTargetError(ValueError):
    """Raised when a live Web target crosses a prohibited network boundary."""


class WebRequestError(RuntimeError):
    """Raised when the primary bounded HTTP request cannot be completed."""

    def __init__(self, message: str, *, timed_out: bool = False) -> None:
        self.timed_out = timed_out
        super().__init__(message)


class InvalidOsintTargetError(ValueError):
    """Raised when a passive OSINT target cannot be normalized safely."""
