import struct
import time
from typing import List


def rolling_rol(x: int, y: int) -> int:
    a = (x) << (y & 31)
    b = (x) >> (32 - (y & 31))
    return (a | b) % (2 ** 32)


def rolling_ror(x: int, y: int) -> int:
    a = (x) >> (y & 31)
    b = (x) << (32 - (y & 31))
    return (a | b) % (2 ** 32)


class LAME:
    c0: int
    c1: int
    grp1: List[int]
    field_D4: int

    def __init__(self) -> None:
        t = time.time()
        self.c0 = 0
        self.c1 = 0
        self.grp1 = [0 for _ in range(17)]
        self.field_D4 = 0
        self.srand(int(t))

    def fpusht(self) -> float:
        rolled = (
            rolling_rol(self.grp1[self.c0], 9) + rolling_rol(self.grp1[self.c1], 13)
        ) % (2 ** 32)
        self.grp1[self.c0] = rolled

        if self.c0 == 0:
            self.c0 = 16
        else:
            self.c0 -= 1

        if self.c1 == 0:
            self.c1 = 16
        else:
            self.c1 -= 1

        low = int(rolled << 20) % (2 ** 32)
        high = ((rolled >> 12) | 0x3FF00000) % (2 ** 32)

        ret = struct.pack("<II", low, high)
        return struct.unpack("<d", ret)[0] - 1.0

    def srand(self, seed: int) -> None:
        for i in range(17):
            seed = (seed * 0x53A9B4FB) % (2 ** 32)
            seed = (1 - seed + 2 ** 32) % (2 ** 32)
            self.grp1[i] = seed

        self.c0 = 0
        self.c1 = 10

        for _ in range(9):
            self.fpusht()

    def get_next(self) -> int:
        self.fpusht()
        x = int(self.fpusht() * 256.0)
        if x < 256:
            return x
        else:
            return 0xFF
