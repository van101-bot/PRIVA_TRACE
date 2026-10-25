from ..interface import WatermarkEngine
from ..errors import (
    WatermarkEmbeddingError,
    WatermarkExtractionError,
)


class PDFWatermarkEngine(WatermarkEngine):
    """
    Interface for the real PDF forensic watermark algorithm.

    DO NOT use PDF metadata as the final watermark mechanism.
    """

    def embed(
        self,
        document: bytes,
        watermark_payload: bytes,
    ) -> bytes:

        raise NotImplementedError(
            "PDF forensic watermark embedding is not implemented yet. "
            "The watermark team must implement the agreed algorithm."
        )

    def extract(
        self,
        document: bytes,
    ) -> bytes:

        raise NotImplementedError(
            "PDF forensic watermark extraction is not implemented yet."
        )