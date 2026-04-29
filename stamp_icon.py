"""
Embed an ICO file into a Windows PE executable via the Win32 UpdateResource API.
Usage: python stamp_icon.py <exe_path> <ico_path>
"""
import sys, struct, os, ctypes

if sys.platform != "win32":
    print("stamp_icon: not Windows, skipping"); sys.exit(0)

if len(sys.argv) != 3:
    print("Usage: stamp_icon.py <exe> <ico>"); sys.exit(1)

exe_path = sys.argv[1]
ico_path = sys.argv[2]

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

if ok:
    print(f"stamp_icon: icon embedded OK into {os.path.basename(exe_path)}")
else:
    sys.exit(1)
