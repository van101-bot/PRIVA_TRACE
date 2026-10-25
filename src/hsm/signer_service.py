from src.hsm.backend import HSMBackend


class KeyBoundSigner:
    """Expose signing operations for one configured backend key."""

    def __init__(self, backend: HSMBackend, key_id: str):
        if not key_id:
            raise ValueError("key_id must not be empty")

        self._backend = backend
        self._key_id = key_id

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message:
            raise ValueError("message must be non-empty bytes")

        return self._backend.sign(self._key_id, message)

    def public_key(self) -> bytes:
        return self._backend.get_public_key(self._key_id)