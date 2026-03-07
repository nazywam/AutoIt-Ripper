from dataclasses import dataclass, field
from .utils import BitStream

JB01_DATA_SIZE = 128 * 1024
JB01_DATA_MASK = JB01_DATA_SIZE - 1

JB01_MINMATCHLEN = 3

JB01_HUFF_LITERAL_ALPHABETSIZE = 256 + 32
JB01_HUFF_LITERAL_LENSTART  = 256

JB01_HUFF_OFFSET_ALPHABETSIZE = 32

JB01_HUFF_LITERAL_INITIALDELAY = JB01_HUFF_LITERAL_ALPHABETSIZE // 4
JB01_HUFF_LITERAL_DELAY = JB01_HUFF_LITERAL_ALPHABETSIZE * 12

JB01_HUFF_OFFSET_INITIALDELAY = JB01_HUFF_OFFSET_ALPHABETSIZE // 4
JB01_HUFF_OFFSET_DELAY = JB01_HUFF_OFFSET_ALPHABETSIZE * 12

JB01_HUFF_LITERAL_FREQMOD = 1
JB01_HUFF_OFFSET_FREQMOD  = 1

JB01_HUFF_MAXCODEBITS = 16


@dataclass
class HuffmanNode:
    frequency:   int  = 1
    child_left:  int  = 0
    child_right: int  = 0
    parent:      int  = 0
    c_value:     int  = 0
    search_me:   bool = False


class HuffmanBitStream(BitStream):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self._huff_literal_tree            = []
        self._huff_offset_tree             = []
        self._huff_literal_fully_active    = False
        self._huff_literal_increment       = 0
        self._huff_literals_left           = 0
        self._huff_offset_fully_active     = False
        self._huff_offset_increment        = 0
        self._huff_offsets_left            = 0

        self._huffman_init()

    @staticmethod
    def _huffman_zero(alphabet_size: int):
        nodes = []
        for i in range(alphabet_size):
            n = HuffmanNode()
            n.frequency   = 1
            n.child_left  = i   # leaf  ↔  children point to self
            n.child_right = i
            nodes.append(n)
        return nodes

    def _huffman_generate(self, tree, alphabet_size: int, freq_mod: int):
        total = (alphabet_size << 1) - 1

        # Extend list to hold internal nodes if needed
        while len(tree) < total:
            tree.append(HuffmanNode())

        for i in range(alphabet_size):
            tree[i].search_me = True

        # Internal nodes are not searched initially
        for i in range(alphabet_size, total):
            tree[i].search_me = False

        root             = (alphabet_size << 1) - 2
        next_blank       = alphabet_size
        end_node         = root + 1

        while next_blank != end_node:
            b1_freq = b2_freq = 0xFFFFFFFF
            b1 = b2 = 0

            for i in range(next_blank):
                if tree[i].search_me:
                    if tree[i].frequency < b2_freq:
                        if tree[i].frequency < b1_freq:
                            b2      = b1
                            b2_freq = b1_freq
                            b1      = i
                            b1_freq = tree[i].frequency
                        else:
                            b2      = i
                            b2_freq = tree[i].frequency

            tree[b1].search_me = False
            tree[b2].search_me = False

            tree[next_blank].frequency   = tree[b1].frequency + tree[b2].frequency
            tree[next_blank].search_me   = True
            tree[next_blank].child_left  = b1
            tree[next_blank].child_right = b2
            tree[b1].parent  = next_blank
            tree[b2].parent  = next_blank
            tree[b1].c_value = 0
            tree[b2].c_value = 1

            next_blank += 1

        # Verify no code exceeds max bits; if so, decay and rebuild
        for i in range(alphabet_size):
            parent = i
            depth  = 0
            while parent != root:
                depth  += 1
                parent  = tree[parent].parent
            if depth > JB01_HUFF_MAXCODEBITS:
                for j in range(alphabet_size):
                    tree[j].frequency = (tree[j].frequency >> 2) + 1
                self._huffman_generate(tree, alphabet_size, freq_mod)
                return

        # Decay old frequencies
        if freq_mod:
            for i in range(alphabet_size):
                tree[i].frequency = (tree[i].frequency >> freq_mod) + 1

    def _huffman_init(self):
        self._huff_literal_tree = self._huffman_zero(JB01_HUFF_LITERAL_ALPHABETSIZE)
        self._huffman_generate(self._huff_literal_tree, JB01_HUFF_LITERAL_ALPHABETSIZE, 0)
        self._huff_literal_fully_active = False
        self._huff_literal_increment    = JB01_HUFF_LITERAL_INITIALDELAY
        self._huff_literals_left        = self._huff_literal_increment

        self._huff_offset_tree = self._huffman_zero(JB01_HUFF_OFFSET_ALPHABETSIZE)
        self._huffman_generate(self._huff_offset_tree, JB01_HUFF_OFFSET_ALPHABETSIZE, 0)
        self._huff_offset_fully_active = False
        self._huff_offset_increment    = JB01_HUFF_OFFSET_INITIALDELAY
        self._huff_offsets_left        = self._huff_offset_increment

    def _read_huffman(self, tree, alphabet_size: int) -> int:
        code = (alphabet_size << 1) - 2
        while tree[code].child_left != code:
            bit = self.get_bits(1)
            if not bit:
                code = tree[code].child_left
            else:
                code = tree[code].child_right
        return code

    def _read_literal(self) -> int:
        literal = self._read_huffman(self._huff_literal_tree, JB01_HUFF_LITERAL_ALPHABETSIZE)
        self._huff_literal_tree[literal].frequency += 1
        self._huff_literals_left -= 1

        if not self._huff_literals_left:
            if self._huff_literal_fully_active:
                self._huff_literals_left = JB01_HUFF_LITERAL_DELAY
                self._huffman_generate(
                    self._huff_literal_tree,
                    JB01_HUFF_LITERAL_ALPHABETSIZE,
                    JB01_HUFF_LITERAL_FREQMOD,
                )
            else:
                self._huff_literal_increment += JB01_HUFF_LITERAL_INITIALDELAY
                if self._huff_literal_increment >= JB01_HUFF_LITERAL_DELAY:
                    self._huff_literal_fully_active = True
                self._huff_literals_left = JB01_HUFF_LITERAL_INITIALDELAY
                self._huffman_generate(
                    self._huff_literal_tree,
                    JB01_HUFF_LITERAL_ALPHABETSIZE,
                    0,
                )

        return literal

    def _read_len(self, code: int) -> int:
        if code <= 263:
            return code - 256
        else:
            code       -= 264
            extra_bits  = (code >> 2) + 1
            msb_value   = 1 << (extra_bits + 2)
            code        = code & 0x0003
            value       = self.get_bits(extra_bits)
            return value + msb_value + (code << extra_bits)

    def _read_offset(self) -> int:
        code = self._read_huffman(self._huff_offset_tree, JB01_HUFF_OFFSET_ALPHABETSIZE)
        self._huff_offset_tree[code].frequency += 1

        if code <= 3:
            value = code
        else:
            code       -= 4
            extra_bits  = (code >> 1) + 1
            msb_value   = 1 << (extra_bits + 1)
            code        = code & 0x0001
            value       = self.get_bits(extra_bits)
            value       = value + msb_value + (code << extra_bits)

        self._huff_offsets_left -= 1

        if not self._huff_offsets_left:
            if self._huff_offset_fully_active:
                self._huff_offsets_left = JB01_HUFF_OFFSET_DELAY
                self._huffman_generate(
                    self._huff_offset_tree,
                    JB01_HUFF_OFFSET_ALPHABETSIZE,
                    JB01_HUFF_OFFSET_FREQMOD,
                )
            else:
                self._huff_offset_increment += JB01_HUFF_OFFSET_INITIALDELAY
                if self._huff_offset_increment >= JB01_HUFF_OFFSET_DELAY:
                    self._huff_offset_fully_active = True
                self._huff_offsets_left = JB01_HUFF_OFFSET_INITIALDELAY
                self._huffman_generate(
                    self._huff_offset_tree,
                    JB01_HUFF_OFFSET_ALPHABETSIZE,
                    0,
                )

        return value