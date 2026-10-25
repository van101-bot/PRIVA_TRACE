"""
SIH26237 - Forensic PDF Watermarking
Day 1 Prototype

Edge-pixel based invisible watermarking.

IMPORTANT:
This is a research prototype for the first implementation stage.
The production version will add:
- better text-line segmentation
- synchronization
- redundancy/error correction
- print-scan robustness
- cryptographic watermark IDs
"""

import hashlib
import io
import math

import numpy as np
import pymupdf
from PIL import Image


class PDFWatermarker:
    """
    Prototype PDF watermarking system.

    The PDF page is rendered to pixels, watermark bits are embedded
    near text-stroke edges, and the modified page is placed back
    into a PDF.
    """

    def __init__(self, dpi=150):
        """
        Parameters
        ----------
        dpi : int
            Resolution used to render PDF pages.
            150 is useful for early testing.
        """

        self.dpi = dpi

    # ==============================================================
    # 1. CREATE WATERMARK ID
    # ==============================================================

    def _create_watermark_id(
        self,
        recipient_id,
        timestamp,
        zkp_proof=None
    ):
        """
        Create the identifier that will eventually be embedded.

        If a ZKP proof is supplied:

            watermark_id = SHA256(ZKP proof)

        Otherwise:

            watermark_id = SHA256(recipient_id + timestamp)
        """

        if zkp_proof is not None:

            if isinstance(zkp_proof, str):
                data = zkp_proof.encode("utf-8")
            else:
                data = bytes(zkp_proof)

        else:

            data = (
                str(recipient_id)
                + str(timestamp)
            ).encode("utf-8")

        return hashlib.sha256(data).hexdigest()

    # ==============================================================
    # 2. CONVERT WATERMARK ID INTO BITS
    # ==============================================================

    def _generate_watermark_bits(
        self,
        recipient_id,
        timestamp,
        zkp_proof=None
    ):
        """
        Generate watermark bits from the watermark ID.

        SHA-256 produces 256 bits.

        Returns
        -------
        bits : list[int]
            List containing 256 zero/one values.

        watermark_id : str
            Hexadecimal SHA-256 identifier.
        """

        watermark_id = self._create_watermark_id(
            recipient_id,
            timestamp,
            zkp_proof
        )

        # Convert hexadecimal SHA-256 into bytes
        digest = bytes.fromhex(watermark_id)

        # Convert every byte into 8 bits
        bits = []

        for byte in digest:

            for i in range(7, -1, -1):

                bit = (byte >> i) & 1

                bits.append(bit)

        return bits, watermark_id

    # ==============================================================
    # 3. RENDER PDF PAGE
    # ==============================================================

    def _render_page(self, page):
        """
        Render a PDF page into a grayscale NumPy image.
        """

        zoom = self.dpi / 72.0

        matrix = pymupdf.Matrix(
            zoom,
            zoom
        )

        pix = page.get_pixmap(
            matrix=matrix,
            colorspace=pymupdf.csGRAY,
            alpha=False
        )

        image = np.frombuffer(
            pix.samples,
            dtype=np.uint8
        )

        image = image.reshape(
            pix.height,
            pix.width
        )

        return image

    # ==============================================================
    # 4. FIND TEXT-LIKE PIXELS
    # ==============================================================

    def _create_binary_text_mask(self, image):
        """
        Convert grayscale image to a binary text mask.

        Black pixels → 1
        White pixels → 0

        A simple threshold is used for the first prototype.
        """

        # Text is generally darker than the page background.
        mask = image < 180

        return mask.astype(np.uint8)

    # ==============================================================
    # 5. FIND EDGE PIXELS
    # ==============================================================

    def _find_edge_pixels(self, binary):
        """
        Find pixels that lie close to the boundary of dark text.

        A pixel is considered an edge candidate if:
        - it is currently white
        - it touches a dark pixel

        This is a simple NumPy-only edge detector.

        Later we can replace this with a more sophisticated
        text-stroke segmentation algorithm.
        """

        dark = binary == 1

        # Shifted versions of the image
        up = np.zeros_like(dark)
        down = np.zeros_like(dark)
        left = np.zeros_like(dark)
        right = np.zeros_like(dark)

        up[1:] = dark[:-1]
        down[:-1] = dark[1:]
        left[:, 1:] = dark[:, :-1]
        right[:, :-1] = dark[:, 1:]

        neighboring_dark = (
            up |
            down |
            left |
            right
        )

        # White pixels next to dark pixels
        edge = (~dark) & neighboring_dark

        return edge

    # ==============================================================
    # 6. SELECT STABLE EMBEDDING POSITIONS
    # ==============================================================
    def _select_embedding_positions(
        self,
        binary,
        number_of_bits
    ):
        """
        Select deterministic carrier positions.

        Instead of depending entirely on the detected edge map,
        positions are selected from a fixed spatial grid.

        This is important for robustness because JPEG compression,
        screenshots and resizing can change individual edge pixels.
        """

        height, width = binary.shape

        positions = []

        # --------------------------------------------------------
        # Leave a small margin around the page
        # --------------------------------------------------------

        margin_y = max(10, height // 20)
        margin_x = max(10, width // 20)

        usable_height = height - (2 * margin_y)
        usable_width = width - (2 * margin_x)

        # --------------------------------------------------------
        # Create a deterministic grid
        # --------------------------------------------------------

        # Dense enough to provide many carrier positions.
        grid_step_y = max(4, usable_height // 40)
        grid_step_x = max(4, usable_width // 40)

        for y in range(
            margin_y,
            height - margin_y,
            grid_step_y
        ):

            for x in range(
                margin_x,
                width - margin_x,
                grid_step_x
            ):

                # ------------------------------------------------
                # Prefer light pixels.
                # ------------------------------------------------

                if binary[y, x] == 0:

                    positions.append(
                        (y, x)
                    )

                if len(positions) >= number_of_bits:
                    return positions

        # --------------------------------------------------------
        # If not enough positions were found, use every grid
        # location regardless of binary value.
        # --------------------------------------------------------

        if len(positions) < number_of_bits:

            positions = []

            for y in range(
                margin_y,
                height - margin_y,
                grid_step_y
            ):

                for x in range(
                    margin_x,
                    width - margin_x,
                    grid_step_x
                ):

                    positions.append(
                        (y, x)
                    )

                    if len(positions) >= number_of_bits:
                        return positions

        return positions 
        # ============================================================
    # SELECT PAIRS FOR ROBUST DIFFERENTIAL EMBEDDING
    # ============================================================
        # ============================================================
    # FIXED DETERMINISTIC CARRIER PAIRS
    # ============================================================

    def _select_embedding_pairs(
        self,
        binary,
        number_of_bits
    ):
        """
        Generate completely deterministic pixel pairs.

        IMPORTANT:
        Carrier locations do NOT depend on the binary image,
        edge detection, text detection, or pixel intensity.

        Therefore the exact same coordinates are used during:

            embedding
            extraction
            JPEG testing

        This prevents synchronization loss after compression.
        """

        height, width = binary.shape

        pairs = []

        # --------------------------------------------------------
        # Safe margins
        # --------------------------------------------------------

        margin_y = max(
            40,
            height // 15
        )

        margin_x = max(
            40,
            width // 15
        )

        # --------------------------------------------------------
        # Fixed spacing.
        #
        # We intentionally use relatively large spacing so that
        # neighboring JPEG blocks have less influence on both
        # pixels in a pair.
        # --------------------------------------------------------

        step_y = 30
        step_x = 30

        # --------------------------------------------------------
        # Generate deterministic pairs.
        #
        # Each pair consists of two pixels on the same row:
        #
        #     P1 ---- P2
        #
        # separated by 6 pixels.
        # --------------------------------------------------------

        pair_distance = 6

        for y in range(
            margin_y,
            height - margin_y,
            step_y
        ):

            for x in range(
                margin_x,
                width - margin_x - pair_distance,
                step_x
            ):

                p1 = (
                    y,
                    x
                )

                p2 = (
                    y,
                    x + pair_distance
                )

                pairs.append(
                    (
                        p1,
                        p2
                    )
                )

                if len(pairs) >= number_of_bits:

                    return pairs

        return pairs
    
    # ============================================================
    # 7. EMBED ONE BIT
    # ============================================================

    def _embed_bit(
        self,
        image,
        position,
        bit
    ):
        """
        Encode one watermark bit into an edge pixel.

        Prototype encoding:

            bit 0 -> grayscale value 190
            bit 1 -> grayscale value 240

        Both values remain above the text threshold (180),
        which helps preserve the edge candidate during
        extraction.
        """

        y, x = position

        if bit == 0:

            image[y, x] = 190

        else:

            image[y, x] = 240
    # ==============================================================
    # 8. MODIFY TEXT EDGES
    # ==============================================================
         # ============================================================
    # DIFFERENTIAL WATERMARK EMBEDDING
    # ============================================================

    def _modify_text_edges(
        self,
        page_image,
        watermark_bits
    ):
        """
        Embed watermark using pairwise intensity differences.

        Each watermark bit is repeated three times.

        Encoding:

            bit 0 -> first pixel darker than second
            bit 1 -> first pixel brighter than second
        """

        page_image = page_image.copy()

        # --------------------------------------------------------
        # 3x redundancy
        # --------------------------------------------------------

        redundant_bits = []

        for bit in watermark_bits:

            redundant_bits.extend(
                [bit, bit, bit]
            )

        # --------------------------------------------------------
        # Create binary mask
        # --------------------------------------------------------

        binary = self._create_binary_text_mask(
            page_image
        )

        # --------------------------------------------------------
        # Select deterministic pixel pairs
        # --------------------------------------------------------

        pairs = self._select_embedding_pairs(
            binary,
            len(redundant_bits)
        )

        embedded = 0

        # --------------------------------------------------------
        # Differential embedding
        # --------------------------------------------------------

        BASE_VALUE = 210
        DIFFERENCE = 45

        LOW_VALUE = (
            BASE_VALUE - DIFFERENCE // 2
        )

        HIGH_VALUE = (
            BASE_VALUE + DIFFERENCE // 2
        )

        for bit, pair in zip(
            redundant_bits,
            pairs
        ):

            (y1, x1), (y2, x2) = pair

            if bit == 0:

                page_image[y1, x1] = LOW_VALUE
                page_image[y2, x2] = HIGH_VALUE

            else:

                page_image[y1, x1] = HIGH_VALUE
                page_image[y2, x2] = LOW_VALUE

            embedded += 1

        return page_image, embedded
    # ==============================================================
    # 9. CONVERT IMAGE BACK TO PDF
    # ==============================================================

    def _image_to_pdf_page(
        self,
        image
    ):
        """
        Convert NumPy image into a PDF-compatible image.
        """

        pil_image = Image.fromarray(
            image
        ).convert("L")

        buffer = io.BytesIO()

        pil_image.save(
            buffer,
            format="PNG"
        )

        return buffer.getvalue()

    # ==============================================================
    # 10. EMBED WATERMARK
    # ==============================================================

    def embed_invisible_watermark(
        self,
        pdf_bytes,
        recipient_id,
        timestamp,
        zkp_proof=None
    ):
        """
        Embed an invisible watermark into a PDF.
        """

        watermark_bits, watermark_id = (
            self._generate_watermark_bits(
                recipient_id,
                timestamp,
                zkp_proof
            )
        )

        original_doc = pymupdf.open(
            stream=pdf_bytes,
            filetype="pdf"
        )

        output_doc = pymupdf.open()

        total_embedded = 0

        for page_number in range(
            len(original_doc)
        ):

            original_page = (
                original_doc[page_number]
            )

            image = self._render_page(
                original_page
            )

            modified_image, embedded = (
                self._modify_text_edges(
                    image,
                    watermark_bits
                )
            )

            total_embedded += embedded

            png_bytes = (
                self._image_to_pdf_page(
                    modified_image
                )
            )

            output_page = output_doc.new_page(
                width=original_page.rect.width,
                height=original_page.rect.height
            )

            output_page.insert_image(
                output_page.rect,
                stream=png_bytes
            )

        watermarked_pdf = (
            output_doc.tobytes(
                garbage=4,
                deflate=True
            )
        )

        original_doc.close()
        output_doc.close()

        print(
            f"Watermark ID: {watermark_id}"
        )

        print(
            f"Bits available: {len(watermark_bits)}"
        )

        print(
            f"Bits embedded: {total_embedded}"
        )

        return watermarked_pdf

    # ==============================================================
    # 11. EXTRACT WATERMARK
    # ==============================================================

        # ============================================================
    # DIFFERENTIAL WATERMARK EXTRACTION
    # ============================================================

    def extract_watermark(
        self,
        watermarked_pdf_bytes
    ):
        """
        Extract a 256-bit watermark using differential decoding.

        Each original bit has three redundant copies.

        For each pair:

            first < second -> 0
            first > second -> 1

        Majority voting is then applied to the three copies.
        """

        doc = pymupdf.open(
            stream=watermarked_pdf_bytes,
            filetype="pdf"
        )

        extracted_redundant_bits = []

        total_bits_needed = 256 * 3

        # --------------------------------------------------------
        # Process pages
        # --------------------------------------------------------

        for page in doc:

            image = self._render_page(
                page
            )

            binary = (
                self._create_binary_text_mask(
                    image
                )
            )

            pairs = self._select_embedding_pairs(
                binary,
                total_bits_needed
            )

            for pair in pairs:

                (y1, x1), (y2, x2) = pair

                pixel1 = int(
                    image[y1, x1]
                )

                pixel2 = int(
                    image[y2, x2]
                )

                # ------------------------------------------------
                # Differential decoding
                # ------------------------------------------------

                if pixel1 < pixel2:

                    bit = 0

                else:

                    bit = 1

                extracted_redundant_bits.append(
                    bit
                )

                if (
                    len(extracted_redundant_bits)
                    >= total_bits_needed
                ):

                    break

            if (
                len(extracted_redundant_bits)
                >= total_bits_needed
            ):

                break

        doc.close()

        # --------------------------------------------------------
        # Check extraction length
        # --------------------------------------------------------

        if (
            len(extracted_redundant_bits)
            < total_bits_needed
        ):

            return {
                "watermark_id": None,
                "confidence": 0.0,
                "bits": extracted_redundant_bits
            }

        # --------------------------------------------------------
        # Majority voting
        # --------------------------------------------------------

        recovered_bits = []

        unanimous_groups = 0

        for start in range(
            0,
            total_bits_needed,
            3
        ):

            group = extracted_redundant_bits[
                start:start + 3
            ]

            ones = sum(group)

            if ones >= 2:

                recovered_bit = 1

            else:

                recovered_bit = 0

            recovered_bits.append(
                recovered_bit
            )

            if ones == 0 or ones == 3:

                unanimous_groups += 1

        # --------------------------------------------------------
        # Convert 256 bits to bytes
        # --------------------------------------------------------

        watermark_bytes = bytearray()

        for start in range(
            0,
            256,
            8
        ):

            byte_value = 0

            for bit in recovered_bits[
                start:start + 8
            ]:

                byte_value = (
                    byte_value << 1
                ) | bit

            watermark_bytes.append(
                byte_value
            )

        watermark_id = (
            bytes(
                watermark_bytes
            ).hex()
        )

        confidence = (
            unanimous_groups / 256
        )

        return {
            "watermark_id": watermark_id,
            "confidence": confidence,
            "bits": recovered_bits
        }