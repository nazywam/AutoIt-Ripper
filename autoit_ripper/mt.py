class MT:
    def __init__(self, seed: int) -> None:
        self.state = [0] * 624
        self.state[0] = seed
        self.i = 0

        for i in range(1, 624):
            last = self.state[i - 1]
            self.state[i] = (i + 0x6C078965 * (last ^ (last >> 30))) & 0xFFFFFFFF

    def twist(self) -> None:
        for i in range(227):
            new_val = self.state[i + 397]
            new_val ^= (
                self.state[i] ^ ((self.state[i + 1] ^ self.state[i]) & 0x7FFFFFFE)
            ) >> 1
            if self.state[i + 1] & 1 != 0:
                new_val ^= 0x9908B0DF
            self.state[i] = new_val

        for i in range(396):
            new_val = self.state[i]
            new_val ^= (
                (
                    self.state[i + 227]
                    ^ ((self.state[i + 228] ^ self.state[i + 227]) & 0x7FFFFFFE)
                )
            ) >> 1
            if self.state[i + 228] & 1 != 0:
                new_val ^= 0x9908B0DF
            self.state[227 + i] = new_val

        new_val = self.state[396]
        new_val ^= (
            (self.state[623] ^ ((self.state[0] ^ self.state[623]) & 0x7FFFFFFE))
        ) >> 1
        if self.state[0] & 1 != 0:
            new_val ^= 0x9908B0DF
        self.state[623] = new_val

    def get_bytes(self, length: int) -> bytes:
        result = []
        for _ in range(length):
            if self.i % 624 == 0:
                self.twist()

            rnd = self.state[self.i % 624]
            rnd = ((((rnd >> 11) ^ rnd) & 0xFF3A58AD) << 7) ^ (rnd >> 11) ^ rnd
            rnd = (
                ((rnd & 0xFFFFDF8C) << 15)
                ^ rnd
                ^ ((((rnd & 0xFFFFDF8C) << 15) ^ rnd) >> 18)
            ) >> 1
            result.append(rnd & 0xFF)
            self.i += 1
        return bytes(result)
