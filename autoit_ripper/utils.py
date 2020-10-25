from datetime import datetime, timezone
from itertools import cycle

from .lame import LAME
from .mt import MT


def filetime_to_dt(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp // 100000000, timezone.utc)


def bytes_to_bitstring(data: bytes) -> str:
    return "".join(bin(x)[2:].zfill(8) for x in data)


class BitStream:
    def __init__(self, data: bytes) -> None:
        self.data = bytes_to_bitstring(data)

    def get_bits(self, num: int) -> int:
        out = int(self.data[:num], 2)
        self.data = self.data[num:]
        return out


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, cycle(key)))


def decrypt_lame(data: bytes, seed: int) -> bytes:
    lame = LAME()
    lame.srand(seed)
    return bytes([x ^ lame.get_next() for x in data])


def decrypt_mt(data: bytes, seed: int) -> bytes:
    key = MT(seed).get_bytes(len(data))
    return xor(data, key)


def crc_data(data: bytes) -> int:
    if len(data) == 0:
        return 0

    dwKey_ECX = 0
    dwKey_ESI = 1
    for b in data:
        dwKey_ESI = (b + dwKey_ESI) % 0xFFF1
        dwKey_ECX = (dwKey_ECX + dwKey_ESI) % 0xFFF1
    return (dwKey_ECX << 0x10) + dwKey_ESI
