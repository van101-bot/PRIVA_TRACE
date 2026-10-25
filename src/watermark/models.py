from dataclasses import dataclass


@dataclass(frozen=True)
class WatermarkedDocument:
    original_hash: str
    watermarked_hash: str
    watermark_id: str
    format: str
    data: bytes