from pathlib import Path
import hashlib

import numpy as np
from PIL import Image


class ImageWatermarker:
    """
    Robust DCT-domain invisible watermarking for images.

    Watermark:
        SHA-256(ZKP proof)

    or, without ZKP:
        SHA-256(recipient_id + timestamp)

    Payload:
        256-bit SHA-256 watermark

    Robustness:
        - 3x repetition of every watermark bit
        - 3 independent DCT coefficient pairs per copy
        - majority voting during extraction
    """

    def __init__(self, strength=40.0):

        self.strength = strength

        # Three different middle-frequency coefficient pairs.
        #
        # Pair 1:
        #       (3,2) <-> (2,3)
        #
        # Pair 2:
        #       (4,1) <-> (1,4)
        #
        # Pair 3:
        #       (2,4) <-> (4,2)
        #
        # These avoid the DC coefficient and very high frequencies.

        self.coefficient_pairs = [
            ((3, 2), (2, 3)),
            ((4, 1), (1, 4)),
            ((2, 4), (4, 2)),
        ]

        # Three copies of every original bit.
        self.redundancy = 3

    # ============================================================
    # WATERMARK ID
    # ============================================================

    def create_watermark_id(
        self,
        recipient_id,
        timestamp,
        zkp_proof=None
    ):
        """
        Create a 256-bit SHA-256 watermark ID.

        If ZKP proof exists:
            SHA256(ZKP proof)

        Otherwise:
            SHA256(recipient_id + timestamp)
        """

        if zkp_proof is not None:
            source = str(zkp_proof)

        else:
            source = (
                str(recipient_id)
                + str(timestamp)
            )

        return hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()

    # ============================================================
    # HEX -> BITS
    # ============================================================

    def watermark_to_bits(self, watermark_id):

        watermark_bytes = bytes.fromhex(
            watermark_id
        )

        bits = []

        for byte in watermark_bytes:

            for shift in range(7, -1, -1):

                bit = (
                    byte >> shift
                ) & 1

                bits.append(bit)

        return bits

    # ============================================================
    # BITS -> HEX
    # ============================================================

    def bits_to_watermark(self, bits):

        watermark_bytes = bytearray()

        for start in range(0, 256, 8):

            byte_value = 0

            for bit in bits[start:start + 8]:

                byte_value = (
                    byte_value << 1
                ) | int(bit)

            watermark_bytes.append(
                byte_value
            )

        return bytes(
            watermark_bytes
        ).hex()

    # ============================================================
    # REPEAT BITS
    # ============================================================

    def _repeat_bits(self, bits):
        """
        Repeat every watermark bit three times.

        Example:

            [1, 0, 1]

        becomes:

            [1, 1, 1, 0, 0, 0, 1, 1, 1]
        """

        repeated = []

        for bit in bits:

            for _ in range(self.redundancy):

                repeated.append(bit)

        return repeated

    # ============================================================
    # MAJORITY VOTE
    # ============================================================

    def _majority_vote(self, bits):
        """
        Recover the original 256 bits from
        three repeated copies.
        """

        recovered = []
        confidence_values = []

        group_size = self.redundancy

        for start in range(
            0,
            len(bits),
            group_size
        ):

            group = bits[
                start:start + group_size
            ]

            if len(group) < group_size:
                break

            ones = sum(group)
            zeros = group_size - ones

            if ones > zeros:

                recovered_bit = 1

                confidence = (
                    ones / group_size
                )

            else:

                recovered_bit = 0

                confidence = (
                    zeros / group_size
                )

            recovered.append(
                recovered_bit
            )

            confidence_values.append(
                confidence
            )

        if not confidence_values:

            return [], 0.0

        confidence = float(
            np.mean(
                confidence_values
            )
        )

        return recovered, confidence

    # ============================================================
    # 1-D DCT
    # ============================================================

    def _dct_1d(self, vector):

        vector = np.asarray(
            vector,
            dtype=np.float64
        )

        n = len(vector)

        result = np.zeros(
            n,
            dtype=np.float64
        )

        factor = np.pi / n

        for k in range(n):

            total = 0.0

            for i in range(n):

                total += (
                    vector[i]
                    * np.cos(
                        factor
                        * (i + 0.5)
                        * k
                    )
                )

            if k == 0:

                alpha = np.sqrt(
                    1.0 / n
                )

            else:

                alpha = np.sqrt(
                    2.0 / n
                )

            result[k] = (
                alpha * total
            )

        return result

    # ============================================================
    # 1-D IDCT
    # ============================================================

    def _idct_1d(self, vector):

        vector = np.asarray(
            vector,
            dtype=np.float64
        )

        n = len(vector)

        result = np.zeros(
            n,
            dtype=np.float64
        )

        factor = np.pi / n

        for i in range(n):

            total = 0.0

            for k in range(n):

                if k == 0:

                    alpha = np.sqrt(
                        1.0 / n
                    )

                else:

                    alpha = np.sqrt(
                        2.0 / n
                    )

                total += (
                    alpha
                    * vector[k]
                    * np.cos(
                        factor
                        * (i + 0.5)
                        * k
                    )
                )

            result[i] = total

        return result

    # ============================================================
    # 2-D DCT
    # ============================================================

    def _dct_2d(self, block):

        block = np.asarray(
            block,
            dtype=np.float64
        )

        temp = np.zeros_like(
            block
        )

        result = np.zeros_like(
            block
        )

        for row in range(8):

            temp[row, :] = (
                self._dct_1d(
                    block[row, :]
                )
            )

        for col in range(8):

            result[:, col] = (
                self._dct_1d(
                    temp[:, col]
                )
            )

        return result

    # ============================================================
    # 2-D IDCT
    # ============================================================

    def _idct_2d(self, block):

        block = np.asarray(
            block,
            dtype=np.float64
        )

        temp = np.zeros_like(
            block
        )

        result = np.zeros_like(
            block
        )

        for row in range(8):

            temp[row, :] = (
                self._idct_1d(
                    block[row, :]
                )
            )

        for col in range(8):

            result[:, col] = (
                self._idct_1d(
                    temp[:, col]
                )
            )

        return result

    # ============================================================
    # EMBED ONE BIT USING MULTIPLE COEFFICIENT PAIRS
    # ============================================================

    def _embed_bit(self, dct_block, bit):

        for pair1, pair2 in self.coefficient_pairs:

            y1, x1 = pair1
            y2, x2 = pair2

            value1 = dct_block[
                y1,
                x1
            ]

            value2 = dct_block[
                y2,
                x2
            ]

            centre = (
                value1 + value2
            ) / 2.0

            difference = (
                self.strength
            )

            if bit == 0:

                dct_block[
                    y1,
                    x1
                ] = (
                    centre
                    - difference / 2.0
                )

                dct_block[
                    y2,
                    x2
                ] = (
                    centre
                    + difference / 2.0
                )

            else:

                dct_block[
                    y1,
                    x1
                ] = (
                    centre
                    + difference / 2.0
                )

                dct_block[
                    y2,
                    x2
                ] = (
                    centre
                    - difference / 2.0
                )

        return dct_block

    # ============================================================
    # EXTRACT ONE BIT USING MULTIPLE COEFFICIENT PAIRS
    # ============================================================

    def _extract_bit(self, dct_block):

        votes = []

        for pair1, pair2 in self.coefficient_pairs:

            y1, x1 = pair1
            y2, x2 = pair2

            value1 = dct_block[
                y1,
                x1
            ]

            value2 = dct_block[
                y2,
                x2
            ]

            if value1 > value2:

                votes.append(1)

            else:

                votes.append(0)

        # Majority vote between the
        # three coefficient pairs.

        ones = sum(votes)
        zeros = len(votes) - ones

        if ones > zeros:

            bit = 1

        else:

            bit = 0

        return bit

    # ============================================================
    # EMBED WATERMARK
    # ============================================================

    def embed_watermark(
        self,
        image,
        recipient_id,
        timestamp,
        zkp_proof=None
    ):
        """
        Embed a 256-bit watermark.

        Each original bit is repeated three times.

        Therefore:

            256 × 3 = 768 embedded blocks

        Each block stores the bit using three
        independent DCT coefficient pairs.
        """

        if isinstance(
            image,
            (str, Path)
        ):

            image = Image.open(
                image
            )

        image = image.convert(
            "L"
        )

        original = np.array(
            image,
            dtype=np.float64
        )

        height, width = (
            original.shape
        )

        usable_height = (
            height // 8
        ) * 8

        usable_width = (
            width // 8
        ) * 8

        working = original[
            :usable_height,
            :usable_width
        ].copy()

        # --------------------------------------------------------
        # CREATE WATERMARK
        # --------------------------------------------------------

        watermark_id = (
            self.create_watermark_id(
                recipient_id,
                timestamp,
                zkp_proof
            )
        )

        original_bits = (
            self.watermark_to_bits(
                watermark_id
            )
        )

        embedded_bits = (
            self._repeat_bits(
                original_bits
            )
        )

        # --------------------------------------------------------
        # CAPACITY
        # --------------------------------------------------------

        available_blocks = (
            (usable_height // 8)
            * (usable_width // 8)
        )

        required_blocks = (
            len(embedded_bits)
        )

        if available_blocks < required_blocks:

            raise ValueError(
                "Image is too small. "
                f"Required blocks: "
                f"{required_blocks}, "
                f"available blocks: "
                f"{available_blocks}."
            )

        # --------------------------------------------------------
        # EMBED
        # --------------------------------------------------------

        bit_index = 0

        for y in range(
            0,
            usable_height,
            8
        ):

            for x in range(
                0,
                usable_width,
                8
            ):

                if bit_index >= required_blocks:

                    break

                block = working[
                    y:y + 8,
                    x:x + 8
                ]

                shifted = (
                    block - 128.0
                )

                dct_block = (
                    self._dct_2d(
                        shifted
                    )
                )

                dct_block = (
                    self._embed_bit(
                        dct_block,
                        embedded_bits[
                            bit_index
                        ]
                    )
                )

                reconstructed = (
                    self._idct_2d(
                        dct_block
                    )
                )

                reconstructed = (
                    reconstructed + 128.0
                )

                working[
                    y:y + 8,
                    x:x + 8
                ] = np.clip(
                    reconstructed,
                    0,
                    255
                )

                bit_index += 1

            if bit_index >= required_blocks:

                break

        # --------------------------------------------------------
        # RESTORE ORIGINAL DIMENSIONS
        # --------------------------------------------------------

        output = original.copy()

        output[
            :usable_height,
            :usable_width
        ] = working

        output = np.clip(
            output,
            0,
            255
        ).astype(
            np.uint8
        )

        return (
            Image.fromarray(
                output
            ),
            watermark_id
        )

    # ============================================================
    # EXTRACT WATERMARK
    # ============================================================

    def extract_watermark(self, image):
        """
        Extract the watermark.

        First:
            3 coefficient pairs vote on each block.

        Then:
            3 repeated blocks vote on each
            original watermark bit.
        """

        if isinstance(
            image,
            (str, Path)
        ):

            image = Image.open(
                image
            )

        image = image.convert(
            "L"
        )

        array = np.array(
            image,
            dtype=np.float64
        )

        height, width = (
            array.shape
        )

        usable_height = (
            height // 8
        ) * 8

        usable_width = (
            width // 8
        ) * 8

        required_bits = (
            256 * self.redundancy
        )

        embedded_bits = []

        # --------------------------------------------------------
        # EXTRACT ALL 768 EMBEDDED BITS
        # --------------------------------------------------------

        for y in range(
            0,
            usable_height,
            8
        ):

            for x in range(
                0,
                usable_width,
                8
            ):

                if len(
                    embedded_bits
                ) >= required_bits:

                    break

                block = array[
                    y:y + 8,
                    x:x + 8
                ]

                shifted = (
                    block - 128.0
                )

                dct_block = (
                    self._dct_2d(
                        shifted
                    )
                )

                bit = (
                    self._extract_bit(
                        dct_block
                    )
                )

                embedded_bits.append(
                    bit
                )

            if len(
                embedded_bits
            ) >= required_bits:

                break

        # --------------------------------------------------------
        # NOT ENOUGH DATA
        # --------------------------------------------------------

        if len(
            embedded_bits
        ) < required_bits:

            return {
                "watermark_id": None,
                "bits": [],
                "embedded_bits": embedded_bits,
                "confidence": 0.0
            }

        # --------------------------------------------------------
        # MAJORITY VOTE
        # --------------------------------------------------------

        recovered_bits, confidence = (
            self._majority_vote(
                embedded_bits
            )
        )

        if len(
            recovered_bits
        ) < 256:

            return {
                "watermark_id": None,
                "bits": recovered_bits,
                "embedded_bits": embedded_bits,
                "confidence": confidence
            }

        recovered_bits = (
            recovered_bits[:256]
        )

        # --------------------------------------------------------
        # RECONSTRUCT SHA-256 ID
        # --------------------------------------------------------

        watermark_id = (
            self.bits_to_watermark(
                recovered_bits
            )
        )

        return {
            "watermark_id": watermark_id,
            "bits": recovered_bits,
            "embedded_bits": embedded_bits,
            "confidence": confidence
        }


# ================================================================
# PSNR
# ================================================================

def calculate_psnr(
    original,
    watermarked
):
    """
    Calculate Peak Signal-to-Noise Ratio.
    """

    original_array = np.asarray(
        original,
        dtype=np.float64
    )

    watermarked_array = np.asarray(
        watermarked,
        dtype=np.float64
    )

    mse = np.mean(
        (
            original_array
            - watermarked_array
        ) ** 2
    )

    if mse == 0:

        return float("inf")

    return (
        10
        * np.log10(
            (255.0 ** 2)
            / mse
        )
    )