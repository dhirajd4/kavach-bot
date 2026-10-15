"""OCR with Tesseract (Hindi + English), TDS §11: Tesseract in the cloud, free, Devanagari.

Images are untrusted input: Pillow's decompression-bomb limit is enforced, the image is
re-encoded to a clean PNG before Tesseract sees it, and Tesseract runs with a timeout.
Nothing is written to disk.
"""

import asyncio
import io
import logging
from typing import Protocol

from PIL import Image, ImageOps

log = logging.getLogger(__name__)

MAX_PIXELS = 40_000_000  # ~ 8000 x 5000; WhatsApp images are far smaller
MIN_WIDTH = 1000  # upscale small screenshots: Tesseract wants ~30 px tall glyphs

Image.MAX_IMAGE_PIXELS = MAX_PIXELS


class BadImage(ValueError):
    pass


class OcrEngine(Protocol):
    async def read(self, image: Image.Image) -> str: ...


def load_image(data: bytes) -> Image.Image:
    """Decode untrusted bytes into an RGB image, or raise BadImage."""
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()  # structural check without decoding pixels
        img: Image.Image = Image.open(io.BytesIO(data))
        img.load()
    except (Image.DecompressionBombError, OSError, SyntaxError, ValueError) as exc:
        raise BadImage(type(exc).__name__) from exc
    img = ImageOps.exif_transpose(img) or img  # phone photos carry rotation in EXIF
    return img.convert("RGB")


def prepare_for_ocr(img: Image.Image) -> bytes:
    gray = ImageOps.grayscale(img)
    if gray.width < MIN_WIDTH:
        scale = MIN_WIDTH / gray.width
        gray = gray.resize((MIN_WIDTH, int(gray.height * scale)), Image.Resampling.LANCZOS)
    gray = ImageOps.autocontrast(gray, cutoff=1)
    buf = io.BytesIO()
    gray.save(buf, format="PNG")
    return buf.getvalue()


class TesseractOcr:
    def __init__(self, langs: str = "hin+eng", timeout_s: float = 15.0) -> None:
        self.langs = langs
        self.timeout_s = timeout_s

    async def read(self, image: Image.Image) -> str:
        png = await asyncio.to_thread(prepare_for_ocr, image)
        proc = await asyncio.create_subprocess_exec(
            "tesseract",
            "stdin",
            "stdout",
            "-l",
            self.langs,
            "--psm",
            "3",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(png), timeout=self.timeout_s)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            log.warning("ocr timed out")
            return ""
        return out.decode("utf-8", errors="ignore")
