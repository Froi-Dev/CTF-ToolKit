class DecoderInputError(ValueError):
    """Raised when decoder-specific request options are invalid."""


class CryptoInputError(ValueError):
    """Raised when cryptographic material or parameters cannot be used safely."""


class ArtifactTooLargeError(ValueError):
    """Raised when an upload crosses the configured artifact-size boundary."""

    def __init__(self, maximum_bytes: int) -> None:
        self.maximum_bytes = maximum_bytes
        super().__init__(f"Artifact exceeds the {maximum_bytes}-byte upload limit.")


class InvalidArtifactError(ValueError):
    """Raised when an uploaded artifact cannot be handled safely."""


class AnalysisFailedError(RuntimeError):
    """Raised when an analyzer fails without exposing internal details to the client."""

    def __init__(self, analyzer: str) -> None:
        self.analyzer = analyzer
        super().__init__(
            f"{analyzer} could not complete this artifact. Check the backend log for the recorded cause."
        )


class AnalysisResourceLimitError(RuntimeError):
    """Raised when analysis cannot continue within the process resource boundary."""

    def __init__(self, analyzer: str) -> None:
        self.analyzer = analyzer
        super().__init__(
            f"{analyzer} exhausted its analysis memory limit for this artifact."
        )


class AnalysisBusyError(RuntimeError):
    """Raised instead of queueing more expensive work behind an active analyzer."""

    def __init__(self, analyzer: str) -> None:
        self.analyzer = analyzer
        super().__init__(
            f"{analyzer} is already analyzing an image. Wait for it to finish before starting another scan."
        )


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


class InvalidAuthenticationSessionError(RuntimeError):
    """Raised when supplied authentication material fails its explicit validation check."""


class InvalidOsintTargetError(ValueError):
    """Raised when a passive OSINT target cannot be normalized safely."""
