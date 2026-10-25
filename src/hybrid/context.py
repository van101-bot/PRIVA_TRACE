from dataclasses import dataclass


@dataclass(frozen=True)
class HybridKeyContext:
    document_id: str
    recipient_id: str
    session_id: str

    def serialize(self) -> bytes:
        fields = (
            self.document_id,
            self.recipient_id,
            self.session_id,
        )

        output = bytearray()

        for value in fields:
            encoded = value.encode("utf-8")

            output.extend(
                len(encoded).to_bytes(
                    4,
                    "big",
                )
            )

            output.extend(encoded)

        return bytes(output)

    def domain_separated(self) -> bytes:
        return (
            b"SIH26237-MULTI-RECIPIENT-KEK-V2|"
            + self.serialize()
        )