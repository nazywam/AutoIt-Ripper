from struct import unpack_from
from typing import Tuple


def blob(data: bytes) -> Tuple[str, int]:
    off = 0
    var = data[off]
    out = ""

    if var == 0x33:
        out = "$"
    elif var == 0x36:
        out = '"'
    elif var == 0x30:
        pass
    elif var == 0x32:
        out = "@"
    elif var == 0x34:
        pass
    elif var == 0x35:
        pass
    off += 1

    key = unpack_from("<H", data[off:])[0]
    off += 2 + 2

    dec = [0] * (key * 2)
    for i in range(key):
        d = unpack_from("<H", data[off:])[0]
        d ^= key
        dec[i * 2 + 0] = d & 0xFF
        dec[i * 2 + 1] = (d >> 8) & 0xFF
        off += 2

    out += bytes(dec).decode("utf-16")
    if var == 0x36:
        out += '" '
    elif var == 0x33 and data[off] == 0x35:
        out += "."
    else:
        out += " "
    return (out, off)


OPCODES = {
    0x05: lambda x: (str(unpack_from("<I", x)[0]) + " ", 1 + 4),
    0x10: lambda x: (str(unpack_from("<Q", x)[0]) + " ", 1 + 8),
    0x20: lambda x: (str(unpack_from("<d", x)[0]) + " ", 1 + 8),
    0x30: blob,
    0x31: blob,
    0x32: blob,
    0x33: blob,
    0x34: blob,
    0x35: blob,
    0x36: blob,
    0x37: blob,
    0x38: blob,
    0x39: blob,
    0x3A: blob,
    0x3B: blob,
    0x3C: blob,
    0x3D: blob,
    0x3E: blob,
    0x3F: blob,
    0x40: lambda x: (", ", 1),
    0x41: lambda x: ("= ", 1),
    0x42: lambda x: ("> ", 1),
    0x43: lambda x: ("< ", 1),
    0x44: lambda x: ("<> ", 1),
    0x45: lambda x: (">= ", 1),
    0x46: lambda x: ("<= ", 1),
    0x47: lambda x: ("( ", 1),
    0x48: lambda x: (") ", 1),
    0x49: lambda x: ("+ ", 1),
    0x4A: lambda x: ("- ", 1),
    0x4B: lambda x: ("/ ", 1),
    0x4C: lambda x: ("* ", 1),
    0x4D: lambda x: ("& ", 1),
    0x4E: lambda x: ("[ ", 1),
    0x4F: lambda x: ("] ", 1),
    0x50: lambda x: ("== ", 1),
    0x51: lambda x: ("^ ", 1),
    0x52: lambda x: ("+= ", 1),
    0x53: lambda x: ("-= ", 1),
    0x54: lambda x: ("/= ", 1),
    0x55: lambda x: ("*= ", 1),
    0x56: lambda x: ("&= ", 1),
    0x57: lambda x: ("? ", 1),
    0x58: lambda x: (": ", 1),
}
