"""
Generate icon.ico from Icon.jpg using classic DIB (BMP) format entries —
the format PyInstaller on Windows accepts unconditionally.
"""
import struct, os
from PIL import Image

src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Icon.jpg")
dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")

img = Image.open(src).convert("RGBA")
sizes = [16, 32, 48, 64, 128, 256]


def make_dib_entry(img, size):
    """Return raw ICO image data in DIB (BITMAPINFOHEADER + masks) format."""
    frame = img.resize((size, size), Image.LANCZOS).convert("RGBA")

    # BITMAPINFOHEADER — height is doubled to account for the AND mask
    bih = struct.pack(
        "<IiiHHIIiiII",
        40,         # biSize
        size,       # biWidth
        size * 2,   # biHeight (XOR + AND stacked)
        1,          # biPlanes
        32,         # biBitCount
        0,          # biCompression BI_RGB
        0,          # biSizeImage (can be 0 for BI_RGB)
        0, 0,       # pixels-per-metre (unused)
        0, 0,       # colors in table (unused for 32bpp)
    )

    # XOR mask: BGRA, rows stored bottom-to-top
    xor = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            r, g, b, a = frame.getpixel((x, y))
            xor += bytes([b, g, r, a])

    # AND mask: 1bpp transparency mask, rows bottom-to-top, padded to DWORD
    row_bytes = ((size + 31) // 32) * 4
    and_mask = b"\x00" * (row_bytes * size)  # all opaque (alpha in XOR handles it)

    return bih + bytes(xor) + and_mask


entries = [(s, make_dib_entry(img, s)) for s in sizes]
n = len(entries)

# ICO file layout: header + directory + image data
header = struct.pack("<HHH", 0, 1, n)

offset = 6 + n * 16  # header (6) + directory entries (n × 16)
directory = b""
for size, data in entries:
    w = size if size < 256 else 0  # 256 is encoded as 0 in the directory
    directory += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(data), offset)
    offset += len(data)

with open(dst, "wb") as f:
    f.write(header)
    f.write(directory)
    for _, data in entries:
        f.write(data)

print(f"icon.ico: {os.path.getsize(dst):,} bytes  ({n} sizes: {sizes})")
