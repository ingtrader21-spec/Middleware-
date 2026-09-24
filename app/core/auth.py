import hmac


class BearerAuthError(ValueError):
    pass


def verify_bearer(authorization: str, secret: str) -> None:
    if not secret:
        raise BearerAuthError("authorization service unavailable")
    scheme, separator, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not supplied:
        raise BearerAuthError("missing or invalid bearer authorization")
    if not hmac.compare_digest(supplied, secret):
        raise BearerAuthError("invalid bearer authorization")
