class ApplicationError(Exception):
    """Base application-level error."""


class DecryptionNotAuthorizedError(ApplicationError):
    """Recipient is not authorized to decrypt the document."""


class ProvenanceCommitError(ApplicationError):
    """Provenance could not be committed to the immutable ledger."""


class WatermarkEmbeddingError(ApplicationError):
    """The forensic watermark could not be embedded."""


class WatermarkExtractionError(ApplicationError):
    """The forensic watermark could not be extracted."""


class AttributionVerificationError(ApplicationError):
    """Cryptographic attribution verification failed."""


class LedgerLookupError(ApplicationError):
    """The provenance ledger could not be queried."""