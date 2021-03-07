from .utils import BitStream, ByteStream, AutoItVersion
from typing import Optional
import logging


# 10 megabytes
MAX_SCRIPT_SIZE = 10 * 10 ** 6


HDR_3_COMP_MAGIC5 = b"EA05"
HDR_3_COMP_MAGIC6 = b"EA06"
HDR_3_COMP_MAGIC0 = b"JB00"
HDR_3_COMP_MAGIC1 = b"JB01"

log = logging.getLogger(__name__)


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

    bin_data = BitStream(stream.get_bytes(None))

    out_data = [0] * uncompressed_size
    cur_output = 0

    while cur_output < uncompressed_size:
        addme = 0
        # version changes...
        if bin_data.get_bits(1) == (version == AutoItVersion.EA06):
            out_data[cur_output] = bin_data.get_bits(8)
            cur_output += 1
        else:
            bb = bin_data.get_bits(15)
            bs = bin_data.get_bits(2)
            if bs == 3:
                addme = 3
                bs = bin_data.get_bits(3)
                if bs == 7:
                    addme = 10
                    bs = bin_data.get_bits(5)
                    if bs == 31:
                        addme = 41
                        bs = bin_data.get_bits(8)
                        if bs == 255:
                            addme = 296
                            while True:
                                bs = bin_data.get_bits(8)
                                if bs != 255:
                                    break
                                addme += 255
            bs += 3 + addme
            i = cur_output - bb
            while True:
                out_data[cur_output] = out_data[i]
                cur_output += 1
                i += 1
                bs -= 1
                if bs <= 0:
                    break
    return bytes(out_data)
