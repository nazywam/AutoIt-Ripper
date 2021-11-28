import logging
from typing import Optional

from .utils import AutoItVersion, BitStream, ByteStream

# 10 megabytes
MAX_SCRIPT_SIZE = 10 * 10 ** 6


EA05_LITERAL = 0
EA06_LITERAL = 1


HDR_3_COMP_MAGIC5 = b"EA05"
HDR_3_COMP_MAGIC6 = b"EA06"
HDR_3_COMP_MAGIC0 = b"JB00"
HDR_3_COMP_MAGIC1 = b"JB01"

log = logging.getLogger(__name__)


def read_match_len(bin_data: BitStream) -> int:
    func_vec = (
        # nLen ibit getMore
        (3, 2, 0b11),  # 3
        (6, 3, 0b111),  # 7
        (13, 5, 0b11111),  # 31
        (44, 8, 255),
        (299, 8, 255),
    )

    length = 0
    length_add = 0

    for (length, bits, more) in func_vec:
        length_add = bin_data.get_bits(bits)
        if length_add != more:
            break
    else:
        while True:
            length += more
            length_add = bin_data.get_bits(bits)
            if length_add != more:
                break

    return length + length_add


def decompress(stream: ByteStream) -> Optional[bytes]:
    version = None
    comp_magic = stream.get_bytes(4)

    if comp_magic == HDR_3_COMP_MAGIC5:
        log.debug("decompress: found a correct EA05 compressed blob")
        version = AutoItVersion.EA05
    elif comp_magic == HDR_3_COMP_MAGIC6:
        log.debug("decompress: found a correct EA06 compressed blob")
        version = AutoItVersion.EA06
    elif comp_magic == HDR_3_COMP_MAGIC0:
        log.debug("decompress: found a correct JB00 compressed blob")
        version = AutoItVersion.JB00
    elif comp_magic == HDR_3_COMP_MAGIC1:
        log.error(
            "decompress: found a correct JB01 compressed blob but it's not yet supported"
        )
        return None
    else:
        log.error("Magic mismatch: %s", comp_magic)
        return None

    uncompressed_size = stream.u32be()
    if uncompressed_size > MAX_SCRIPT_SIZE:
        log.error("Uncompressed script size is larger than allowed")
        return None

    literal_symbol = EA06_LITERAL if version == AutoItVersion.EA06 else EA05_LITERAL
    bin_data = BitStream(stream.get_bytes(None))

    out_data = bytearray()

    while len(out_data) < uncompressed_size:
        if bin_data.get_bits(1) == literal_symbol:
            out_data.append(bin_data.get_bits(8))
        else:
            if version in (AutoItVersion.EA05, AutoItVersion.EA06):
                offset = bin_data.get_bits(0xF)
                match_len = read_match_len(bin_data)
            else:
                offset = bin_data.get_bits(0xD) + 3
                match_len = bin_data.get_bits(0x4) + 3

            fillup = match_len - offset
            append_data = out_data[-offset:][:match_len]

            def repeat_cut(data: bytes, length: int) -> bytes:
                repeat = length // len(data) + 1
                return (data * repeat)[:length]

            if fillup > 0:
                if fillup == 1:
                    append_data.extend(append_data[:1])
                else:
                    append_data.extend(repeat_cut(append_data, fillup))

            out_data.extend(append_data)
    return bytes(out_data)
