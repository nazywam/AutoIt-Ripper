from datetime import datetime, timedelta
from enum import Enum
from itertools import cycle
from struct import unpack_from
from typing import Optional, Tuple
from zlib import adler32

from .lame import LAME
from .mt import MT


class AutoItVersion(Enum):
    EA05 = 0
    EA06 = 1
    JB00 = 2
    JB01 = 3


def filetime_to_dt(timestamp: int) -> datetime:
    # timestamp it FileTime (number of 100-nanosecond intervals since January 1, 1601)
    return datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)


def bytes_to_bitstring(data: bytes) -> str:
    return "".join(bin(x)[2:].zfill(8) for x in data)


class BitStream:
    def __init__(self, data: bytes) -> None:
        self._data = bytes_to_bitstring(data)
        self._offset = 0

    def get_bits(self, num: int) -> int:
        data = self._data[self._offset: self._offset + num]
        self._offset += num
        return int(data, 2)


class ByteStream:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def skip_bytes(self, num: int) -> None:
        self._offset += num

    def get_bytes(self, num: Optional[int]) -> bytes:
        if num is None:
            num = len(self._data) - self._offset

        data = self._data[self._offset: self._offset + num]
        self._offset += num
        return data

    def _int(self, len: int, signed: bool) -> int:
        return int.from_bytes(
            bytes=self.get_bytes(len), byteorder="little", signed=signed
        )

    def _int_be(self, len: int, signed: bool) -> int:
        return int.from_bytes(bytes=self.get_bytes(len), byteorder="big", signed=signed)

    def f64(self) -> float:
        return unpack_from("<d", self.get_bytes(8))[0]

    def u8(self) -> int:
        return self._int(1, False)

    def i8(self) -> int:
        return self._int(1, True)

    def u16(self) -> int:
        return self._int(2, False)

    def i16(self) -> int:
        return self._int(2, True)

    def u32(self) -> int:
        return self._int(4, False)

    def u32be(self) -> int:
        return self._int_be(4, False)

    def i32(self) -> int:
        return self._int(4, True)

    def u64(self) -> int:
        return self._int(8, False)

    def i64(self) -> int:
        return self._int(8, True)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, cycle(key)))


def decrypt_lame(data: bytes, seed: int) -> bytes:
    lame = LAME()
    lame.srand(seed)
    lame_stream = lame.get_n_next(len(data))
    return xor(data, lame_stream)


def decrypt_mt(data: bytes, seed: int) -> bytes:
    key = MT(seed).get_bytes(len(data))
    return xor(data, key)


def crc_data(data: bytes) -> int:
    return adler32(data)


class DecryptorBase:
    au3_Unicode: Optional[bool] = None
    au3_ResType: Optional[int] = None
    au3_ResSubType: Optional[Tuple[int, int]] = None
    au3_ResName: Optional[Tuple[int, int]] = None
    au3_ResSize: Optional[int] = None
    au3_ResCrcCompressed: Optional[int] = None
    au3_ResContent: Optional[int] = None

    def decrypt(self, data: bytes, key: int) -> bytes:
        raise NotImplementedError


class EA05Decryptor(DecryptorBase):
    au3_Unicode = False
    au3_ResType = 0x16FA
    au3_ResSubType = (0x29BC, 0xA25E)
    au3_ResName = (0x29AC, 0xF25E)
    au3_ResSize = 0x45AA
    au3_ResCrcCompressed = 0xC3D2
    au3_ResContent = 0x22AF

    def decrypt(self, data: bytes, key: int) -> bytes:
        return decrypt_mt(data, key)


class EA06Decryptor(DecryptorBase):
    au3_Unicode = True
    au3_ResType = 0x18EE
    au3_ResSubType = (0xADBC, 0xB33F)
    au3_ResName = (0xF820, 0xF479)
    au3_ResSize = 0x87BC
    au3_ResCrcCompressed = 0xA685
    au3_ResContent = 0x2477

    def decrypt(self, data: bytes, key: int) -> bytes:
        return decrypt_lame(data, key)
