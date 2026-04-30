"""
Embed an ICO file into a Windows PE executable via the Win32 UpdateResource API.

PyInstaller-safe: the Win32 BeginUpdateResource/EndUpdateResource APIs do not
preserve a PE overlay (data appended past the end of the last section).
PyInstaller's --onefile bootloader stores its bundled archive exactly there.
We snapshot the overlay before stamping and re-append it afterwards so the
resulting exe still has both a rich multi-size icon AND a working PKG archive.

Usage: python stamp_icon.py <exe_path> <ico_path>
"""
import sys, struct, os, ctypes

if sys.platform != "win32":
    print("stamp_icon: not Windows, skipping"); sys.exit(0)

if len(sys.argv) != 3:
    print("Usage: stamp_icon.py <exe> <ico>"); sys.exit(1)

exe_path = sys.argv[1]
ico_path = sys.argv[2]

# ── Snapshot PyInstaller overlay (everything after the last PE section) ──────
try:
    import pefile
except ImportError:
    print("stamp_icon: pefile is required (pip install pefile)"); sys.exit(1)

_pe_probe = pefile.PE(exe_path, fast_load=True)
overlay_offset = _pe_probe.get_overlay_data_start_offset()
_pe_probe.close()

overlay_bytes = b""
if overlay_offset is not None:
    with open(exe_path, "rb") as f:
        f.seek(overlay_offset)
        overlay_bytes = f.read()
    print(f"stamp_icon: snapshotted PE overlay = {len(overlay_bytes):,} bytes")

# ── Parse ICO ─────────────────────────────────────────────────────────────────
with open(ico_path, "rb") as f:
    ico = f.read()

_, typ, count = struct.unpack_from("<HHH", ico, 0)
assert typ == 1, "Not a valid ICO file"

images = []
for i in range(count):
    o = 6 + i * 16
    w, h, cc, res, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", ico, o)
    images.append((w, h, cc, res, planes, bpp, ico[offset: offset + size]))

# ── Build RT_GROUP_ICON resource ──────────────────────────────────────────────
# GRPICONDIR header + GRPICONDIRENTRY × n
grp = struct.pack("<HHH", 0, 1, count)
for idx, (w, h, cc, res, planes, bpp, data) in enumerate(images, 1):
    # GRPICONDIRENTRY: same as ICONDIRENTRY but last field is WORD resource ID
    grp += struct.pack("<BBBBHHIH",
        w if w < 256 else 0,   # bWidth  (256 stored as 0)
        h if h < 256 else 0,   # bHeight
        cc,                    # bColorCount
        res,                   # bReserved
        planes,                # wPlanes
        bpp,                   # wBitCount
        len(data),             # dwBytesInRes  ← must be DWORD (I, unsigned)
        idx,                   # nID           ← resource ID
    )

# ── Win32 UpdateResource ──────────────────────────────────────────────────────
k32 = ctypes.windll.kernel32

# lpType / lpName accept either a string pointer OR a MAKEINTRESOURCE integer.
# Declare them as c_void_p so ctypes passes integers as-is (pointer-width value).
k32.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_bool]
k32.BeginUpdateResourceW.restype  = ctypes.c_void_p

k32.UpdateResourceW.argtypes = [
    ctypes.c_void_p,  # hUpdate
    ctypes.c_void_p,  # lpType  (MAKEINTRESOURCE int)
    ctypes.c_void_p,  # lpName  (MAKEINTRESOURCE int)
    ctypes.c_ushort,  # wLanguage
    ctypes.c_void_p,  # lpData  (raw buffer — c_char_p would truncate at null bytes)
    ctypes.c_ulong,   # cbData
]
k32.UpdateResourceW.restype = ctypes.c_bool

k32.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_bool]
k32.EndUpdateResourceW.restype  = ctypes.c_bool

RT_ICON       = 3
RT_GROUP_ICON = 14
LANG_NEUTRAL  = 0

handle = k32.BeginUpdateResourceW(exe_path, False)
if not handle:
    print(f"stamp_icon: BeginUpdateResource failed (err={k32.GetLastError()})")
    sys.exit(1)

ok = True
for idx, (_, _, _, _, _, _, data) in enumerate(images, 1):
    buf = ctypes.create_string_buffer(data)
    if not k32.UpdateResourceW(handle, RT_ICON, idx, LANG_NEUTRAL, buf, len(data)):
        print(f"stamp_icon: RT_ICON {idx} failed (err={k32.GetLastError()})")
        ok = False

grp_buf = ctypes.create_string_buffer(grp)
if not k32.UpdateResourceW(handle, RT_GROUP_ICON, 1, LANG_NEUTRAL, grp_buf, len(grp)):
    print(f"stamp_icon: RT_GROUP_ICON failed (err={k32.GetLastError()})")
    ok = False

committed = k32.EndUpdateResourceW(handle, not ok)
if not committed:
    print(f"stamp_icon: EndUpdateResource failed (err={k32.GetLastError()})")
    sys.exit(1)

if not ok:
    sys.exit(1)

# ── Restore PyInstaller overlay if BeginUpdateResource stripped it ───────────
if overlay_bytes:
    _pe_after = pefile.PE(exe_path, fast_load=True)
    new_overlay_offset = _pe_after.get_overlay_data_start_offset()
    _pe_after.close()
    new_section_end = new_overlay_offset if new_overlay_offset is not None else os.path.getsize(exe_path)
    with open(exe_path, "r+b") as f:
        # Drop whatever overlay (if any) the resource update produced, then re-attach ours.
        f.truncate(new_section_end)
        f.seek(0, os.SEEK_END)
        f.write(overlay_bytes)
    print(f"stamp_icon: restored PE overlay ({len(overlay_bytes):,} bytes)")

print(f"stamp_icon: icon embedded OK into {os.path.basename(exe_path)}")
