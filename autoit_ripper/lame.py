import struct
from typing import List


def rolling_rol(x: int, y: int) -> int:
    a = (x) << (y & 31)
    b = (x) >> (32 - (y & 31))
    return (a | b) & 0xFFFFFFFF


class LAME:
    c0: int
    c1: int
    grp1: List[int]
    field_D4: int

    def __init__(self) -> None:
        self.c0 = 0
        self.c1 = 0
        self.grp1 = [0 for _ in range(17)]
        self.field_D4 = 0

    def fpusht(self) -> float:
        rolled = (
            rolling_rol(self.grp1[self.c0], 9) + rolling_rol(self.grp1[self.c1], 13)
        ) & 0xFFFFFFFF
        self.grp1[self.c0] = rolled

        if self.c0 == 0:
            self.c0 = 16
        else:
            self.c0 -= 1

        if self.c1 == 0:
            self.c1 = 16
        else:
            self.c1 -= 1

        low = int(rolled << 20) & 0xFFFFFFFF
        high = ((rolled >> 12) | 0x3FF00000) & 0xFFFFFFFF

        ret = struct.pack("<II", low, high)
        return struct.unpack("<d", ret)[0] - 1.0

    def srand(self, seed: int) -> None:
        for i in range(17):
            seed = (1 - seed * 0x53A9B4FB) & 0xFFFFFFFF
            self.grp1[i] = seed

        self.c0 = 0
        self.c1 = 10

        for _ in range(9):
            self.fpusht()

    def get_next(self) -> int:
        self.fpusht()
        return int(self.fpusht() * 256.0)

    def get_n_next(self, num: int) -> bytearray:
        ret = bytearray(num)
        for i in range(num):
            self.fpusht()
            x = int(self.fpusht() * 256.0)
            ret[i] = x
        return ret
