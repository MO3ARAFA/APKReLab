"""Generate the extension's PNG icons with the stdlib only (no Pillow)."""
import struct
import zlib
from pathlib import Path


def png(size: int) -> bytes:
    rows = []
    c, r = (size - 1) / 2, size * 0.42
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            t = (x + y) / (2 * size)
            base = (int(37 + 40 * t), int(99 + 40 * t), int(235 - 30 * t))
            inside = (x - c) ** 2 + (y - c) ** 2 <= r * r
            ring = (x - c) ** 2 + (y - c) ** 2 <= (r * 0.55) ** 2
            px = (255, 255, 255) if inside and not ring else base
            row += bytes([*px, 255])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def make(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for s in (16, 32, 48, 128):
        (dest / f"icon{s}.png").write_bytes(png(s))


if __name__ == "__main__":
    make(Path(__file__).parent / "crm_clipper_extension" / "icons")
