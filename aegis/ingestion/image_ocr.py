"""Ingestion adapter for images with multi-pass OCR and EXIF extraction (§5.1)."""

import io
from typing import TYPE_CHECKING
from PIL import Image, ImageOps, ExifTags

from aegis.ingestion.base import BaseAdapter, OversizeContentError
from aegis.models import InputSource, Segment
from aegis.policy.config import get_policy
from server.routes_health import is_ocr_available

if TYPE_CHECKING:
    from aegis.policy.config import PolicyConfig


class ImageOcrAdapter(BaseAdapter):
    """Adapter for IMAGE source with multi-pass OCR and metadata extraction."""

    source = InputSource.IMAGE

    def _extract_exif_and_info(self, img: Image.Image) -> list[tuple[str, str, str]]:
        """Extract EXIF and image info metadata chunks. Returns list of (text, loc, origin)."""
        results = []

        # 1. EXIF data
        try:
            exif = img.getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        # Some EXIF tags are UTF-16 or ASCII bytes
                        try:
                            val_str = value.decode("utf-16le").rstrip("\x00").strip()
                        except Exception:
                            val_str = value.decode("utf-8", errors="replace").rstrip("\x00").strip()
                    else:
                        val_str = str(value).strip()

                    if val_str and tag_name in (
                        "ImageDescription",
                        "UserComment",
                        "XPComment",
                        "XPTitle",
                        "XPSubject",
                        "XPKeywords",
                        "Software",
                        "Artist",
                        "Copyright",
                    ):
                        results.append((val_str, f"exif:{tag_name}", "exif"))
        except Exception:
            pass

        # 2. PNG info text chunks
        try:
            for k, v in img.info.items():
                if isinstance(v, str) and v.strip() and k not in ("exif", "icc_profile"):
                    results.append((v.strip(), f"png_chunk:{k}", "metadata"))
        except Exception:
            pass

        return results

    def _run_ocr_pass(self, img: Image.Image) -> str:
        """Run pytesseract on a single PIL image."""
        import pytesseract

        text = pytesseract.image_to_string(img, config="--psm 6")
        return text.strip()

    def _multi_pass_ocr(self, img: Image.Image) -> list[tuple[str, str, str | None, str]]:
        """Perform multi-pass OCR to detect visible vs faint/enhanced text.
        Returns list of (text, location, hidden_reason, origin).
        """
        import pytesseract

        results = []
        gray = img.convert("L")

        # Pass 0: Standard grayscale
        try:
            base_text = self._run_ocr_pass(gray)
        except Exception:
            base_text = ""

        if base_text:
            results.append((base_text, "image:base_ocr", None, "ocr"))

        # Enhanced passes
        enhanced_passes = [
            ("autocontrast", ImageOps.autocontrast(gray)),
            ("equalize", ImageOps.equalize(gray)),
            ("invert", ImageOps.invert(gray)),
            ("upscale_2x", gray.resize((gray.width * 2, gray.height * 2), Image.Resampling.LANCZOS)),
        ]

        found_enhanced_texts = set()
        base_words = set(base_text.lower().split())

        for pass_name, enh_img in enhanced_passes:
            try:
                enh_text = self._run_ocr_pass(enh_img)
            except Exception:
                continue

            if not enh_text:
                continue

            enh_words = set(enh_text.lower().split())
            new_words = enh_words - base_words

            # If enhanced pass recovered significantly new words not in base OCR
            if len(new_words) >= 2 and enh_text not in found_enhanced_texts:
                found_enhanced_texts.add(enh_text)
                results.append((enh_text, f"image:{pass_name}", "faint_ocr", "hidden"))

        return results

    def extract(
        self,
        data: bytes | str,
        *,
        filename: str | None = None,
        policy: "PolicyConfig | None" = None,
    ) -> list[Segment]:
        pol = policy or get_policy()

        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if len(raw_bytes) > pol.limits.max_upload_bytes:
            raise OversizeContentError(
                f"Image file size exceeds limit of {pol.limits.max_upload_bytes} bytes"
            )

        try:
            img = Image.open(io.BytesIO(raw_bytes))
        except Exception as e:
            # If not an image, raise error
            raise OversizeContentError(f"Failed to open image file: {e}") from e

        # Check megapixels
        mp = (img.width * img.height) / 1_000_000.0
        if mp > pol.limits.max_image_megapixels:
            raise OversizeContentError(
                f"Image size {mp:.1f} MP exceeds limit of {pol.limits.max_image_megapixels} MP"
            )

        segments: list[Segment] = []
        seg_idx = 0

        # 1. EXIF and info chunks
        for text, loc, origin in self._extract_exif_and_info(img):
            segments.append(
                Segment(
                    id=f"seg-img-{seg_idx}",
                    text=text,
                    origin=origin,
                    location=loc,
                    hidden_reason=None,
                )
            )
            seg_idx += 1

        # 2. OCR passes (if Tesseract is available)
        if is_ocr_available():
            try:
                for text, loc, reason, orig in self._multi_pass_ocr(img):
                    segments.append(
                        Segment(
                            id=f"seg-img-{seg_idx}",
                            text=text,
                            origin=orig,
                            location=loc,
                            hidden_reason=reason,
                        )
                    )
                    seg_idx += 1
            except Exception:
                pass
        else:
            # Degrade gracefully: indicate OCR unavailable in a segment if no metadata was found
            if not segments:
                segments.append(
                    Segment(
                        id=f"seg-img-{seg_idx}",
                        text="[OCR unavailable on host]",
                        origin="ocr",
                        location="image:fallback",
                        hidden_reason=None,
                    )
                )

        return segments
