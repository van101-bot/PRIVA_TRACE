class SIH26237Error(Exception):
    """Base exception for the SIH26237 system."""


class DecryptionError(SIH26237Error):
    """Raised when document decryption fails."""


class RecipientNotFoundError(SIH26237Error):
    """Raised when a recipient does not exist."""


class RecipientRevokedError(SIH26237Error):
    """Raised when a revoked recipient/key attempts an operation."""


class InvalidSignatureError(SIH26237Error):
    """Raised when a digital signature is invalid."""


class InvalidProvenanceError(SIH26237Error):
    """Raised when provenance validation fails."""


class WatermarkError(SIH26237Error):
    """Base watermark exception."""


class WatermarkNotFoundError(WatermarkError):
    """Raised when a watermark cannot be extracted."""


class DocumentIntegrityError(SIH26237Error):
    """Raised when document integrity validation fails."""


class LedgerError(SIH26237Error):
    """Base ledger exception."""