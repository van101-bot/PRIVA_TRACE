from abc import ABC, abstractmethod


class WatermarkEngine(ABC):

    @abstractmethod
    def embed(
        self,
        document: bytes,
        watermark_payload: bytes,
    ) -> bytes:
        """
        Embed invisible forensic watermark into document.
        """
        raise NotImplementedError

    @abstractmethod
    def extract(
        self,
        document: bytes,
    ) -> bytes:
        """
        Extract forensic watermark payload from document.
        """
        raise NotImplementedError