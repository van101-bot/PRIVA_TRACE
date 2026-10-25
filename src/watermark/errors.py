class WatermarkEngineError(Exception):
    pass


class WatermarkEmbeddingError(WatermarkEngineError):
    pass


class WatermarkExtractionError(WatermarkEngineError):
    pass


class WatermarkIntegrityError(WatermarkEngineError):
    pass