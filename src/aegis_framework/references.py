"""Authenticated opaque references kept outside workflow module imports."""

from __future__ import annotations

import base64
import binascii
import os
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import TypeAdapter, ValidationError

from aegis_framework.domain import Identifier

_IDENTIFIER = TypeAdapter(Identifier)


class TenantReferenceCodec:
    """Encrypt tenant routing context before it enters framework history."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("tenant reference key must contain at least 32 bytes")
        derived = sha256(b"aegis-tenant-reference\x00" + key).digest()
        self._cipher = AESGCM(derived)

    def encode(self, tenant_id: str) -> str:
        validated = _IDENTIFIER.validate_python(tenant_id)
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(
            nonce,
            validated.encode(),
            b"aegis-tenant-reference-v1",
        )
        token = base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")
        return f"tenantref:{token}"

    def decode(self, reference: str) -> str:
        if not reference.startswith("tenantref:") or len(reference) > 512:
            raise ValueError("tenant reference is invalid")
        try:
            token = reference.partition(":")[2]
            padding = "=" * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(token + padding)
            plaintext = self._cipher.decrypt(
                decoded[:12],
                decoded[12:],
                b"aegis-tenant-reference-v1",
            )
            return _IDENTIFIER.validate_python(plaintext.decode())
        except (
            binascii.Error,
            InvalidTag,
            UnicodeDecodeError,
            ValueError,
            ValidationError,
        ) as exc:
            raise ValueError("tenant reference is invalid") from exc
