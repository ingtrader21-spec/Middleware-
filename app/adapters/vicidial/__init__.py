"""Fail-closed VICIdial private API adapter."""

from app.adapters.vicidial.mtls_client import (
    VicidialMtlsClient,
    VicidialMtlsError,
)

__all__ = ["VicidialMtlsClient", "VicidialMtlsError"]
