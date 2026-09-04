"""Generate and save QR code images."""

import os
from importlib import import_module

try:
    qrcode = import_module("qrcode")
except ImportError as exc:
    raise ImportError(
        "Install the QR-code dependency with 'pip install qrcode[pil]'."
    ) from exc


def generate_and_save_qr(data: str, filename: str = "secure_qr.png") -> str:
    """Encodes the target string into a QR image and displays it."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    if not filename.lower().endswith(".png"):
        filename += ".png"

    abs_path = os.path.abspath(filename)
    img.save(abs_path)
    img.show()
    return abs_path
