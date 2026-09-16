#!/usr/bin/env python3
"""Generate status-tinted ICO variants from the brand ICO.

Usage:
    python scripts/tint_ico.py cmd/hooshix-agent-tray/hooshix.ico \
        --green cmd/hooshix-agent-tray/hooshix-green.ico \
        --yellow cmd/hooshix-agent-tray/hooshix-yellow.ico \
        --red cmd/hooshix-agent-tray/hooshix-red.ico

Each ICO frame (PNG-compressed, as produced by make-ico.ps1) is decoded,
converted to grayscale luminance, and recolored with the target hue at full
saturation so the brand glyph silhouette is preserved and the status color
reads clearly at 16 px. The output keeps the source's frame size list.
"""
from __future__ import annotations

import argparse
import colorsys
import io
import struct
import sys

from PIL import Image

# Status hues (degrees). Green = healthy, amber = degraded/reconnecting,
# red = terminal failure.
HUES = {"green": 130, "yellow": 45, "red": 5}


def parse_ico(data: bytes) -> tuple[list[dict], list[Image.Image]]:
    """Parse an ICO container, returning the directory entries and frames."""
    reserved, icon_type, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or icon_type != 1:
        raise ValueError("not an ICO file")
    entries = []
    frames: list[Image.Image] = []
    offset = 6 + 16 * count
    for index in range(count):
        entry = data[6 + 16 * index : 6 + 16 * (index + 1)]
        width, height, color_count, reserved_b, planes, bit_count, size, img_off = (
            struct.unpack("<BBBBHHII", entry)
        )
        frame_data = data[img_off : img_off + size]
        # Frames are PNG-compressed per make-ico.ps1; fall back to BMP frames
        # (skip the doubled height mask) if the PNG signature is missing.
        if frame_data[:8] == b"\x89PNG\r\n\x1a\n":
            image = Image.open(io.BytesIO(frame_data)).convert("RGBA")
        else:
            image = Image.open(io.BytesIO(frame_data))
            image = image.crop((0, 0, image.width, image.height // 2)).convert("RGBA")
        entries.append(
            {
                "width": width,
                "height": height,
                "color_count": color_count,
                "reserved": reserved_b,
                "planes": planes,
                "bit_count": bit_count,
            }
        )
        frames.append(image)
        offset += size
    return entries, frames


def tint_frame(image: Image.Image, hue: float) -> Image.Image:
    """Recolor a frame: keep the glyph luminance, apply the status hue."""
    result = Image.new("RGBA", image.size)
    source = image.load()
    target = result.load()
    for y in range(image.height):
        for x in range(image.width):
            r, g, b, a = source[x, y]
            if a == 0:
                target[x, y] = (0, 0, 0, 0)
                continue
            # Luminance keeps the glyph shape; dark glyph pixels map to the
            # brightest status color so the tint reads at 16 px.
            luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0
            value = 1.0 - luminance
            value = max(0.25, value)
            fr, fg, fb = colorsys.hls_to_rgb(hue / 360.0, value / 2.0, 1.0)
            target[x, y] = (int(fr * 255), int(fg * 255), int(fb * 255), a)
    return result


def write_ico(path: str, entries: list[dict], frames: list[Image.Image]) -> None:
    """Write frames as a PNG-compressed ICO container."""
    encoded = []
    for image in frames:
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded.append(buffer.getvalue())

    with open(path, "wb") as handle:
        handle.write(struct.pack("<HHH", 0, 1, len(entries)))
        offset = 6 + 16 * len(entries)
        for entry, blob in zip(entries, encoded):
            handle.write(
                struct.pack(
                    "<BBBBHHII",
                    entry["width"],
                    entry["height"],
                    entry["color_count"],
                    entry["reserved"],
                    entry["planes"],
                    entry["bit_count"],
                    len(blob),
                    offset,
                )
            )
            offset += len(blob)
        for blob in encoded:
            handle.write(blob)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="source multi-resolution ICO")
    parser.add_argument("--green", required=True, help="output path for the green (healthy) variant")
    parser.add_argument("--yellow", required=True, help="output path for the yellow (degraded) variant")
    parser.add_argument("--red", required=True, help="output path for the red (terminal) variant")
    args = parser.parse_args()

    with open(args.source, "rb") as handle:
        data = handle.read()
    entries, frames = parse_ico(data)

    outputs = {
        name: (path, HUES[name]) for name, path in
        (("green", args.green), ("yellow", args.yellow), ("red", args.red))
    }
    for name, (path, hue) in outputs.items():
        tinted = [tint_frame(frame, hue) for frame in frames]
        write_ico(path, entries, tinted)
        print(f"tinted: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
