class PostizError(Exception):
    """Normalized provider error safe for API responses and audit records."""

    def __init__(self, code: str, message: str, *, retryable: bool = False, status: int | None = None, unknown_result: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.status = status
        self.unknown_result = unknown_result
