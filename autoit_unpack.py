from typing import Optional, Tuple
import struct
from opcodes import OPCODES
import logging
from utils import BitStream, decrypt_lame, crc_data

# 10 megabytes
MAX_SCRIPT_SIZE = 10 * 10**6


log = logging.getLogger(__name__)


def decompress_ea06(data: bytes) -> Optional[bytes]:
    if data[:4] != b"EA06":
        log.error("Magic mismtach")
        return None

    uncompressed_size = struct.unpack(">I", data[4:8])[0]
    if uncompressed_size > MAX_SCRIPT_SIZE:
        log.error("Uncompressed script size is larger than allowed")
        return None

    data = data[8:]
    bin_data = BitStream(data)

    out_data = [0] * uncompressed_size
    cur_output = 0

    while cur_output < uncompressed_size:
        addme = 0
        if bin_data.get_bits(1) == 1:
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


def deassemble_script(script_data: bytes) -> str:
    section_num = struct.unpack("<I", script_data[:4])[0]
    section_index = 0
    offset = 4

    out = ""
    while section_index < section_num:
        opcode = script_data[offset]
        if opcode in OPCODES:
            add, off = OPCODES[opcode](script_data[offset:])
        elif opcode == 0x7f:
            section_index += 1
            add, off = "\r\n", 0 + 1
        elif opcode <= 0x0F:
            add, off = "", 4 + 1
        elif opcode <= 0x1F:
            add, off = "", 8 + 1
        elif opcode <= 0x2F:
            add, off = "", 8 + 1
        else:
            add, off = "", 0 + 1

        out += add
        offset += off
    return out


def parse_au3_header(data: bytes) -> Optional[Tuple[int, Optional[str]]]:
    off = 0
    file_str = decrypt_lame(data[off:][:4], 0x18EE)
    if file_str != b"FILE":
        return None

    off += 4
    flag = struct.unpack("<I", data[off:][:4])[0] ^ 0xADBC
    off += 4
    auto_str = decrypt_lame(data[off:][: flag * 2], 0xB33F + flag).decode("utf-16")
    log.debug("Found a new autoit string: %s", auto_str)
    off += flag * 2
    path_len = struct.unpack("<I", data[off:][:4])[0] ^ 0xF820
    off += 4
    path = decrypt_lame(data[off:][: path_len * 2], 0xF479 + path_len).decode("utf-16")
    log.debug("Found a new path: %s", path)
    off += path_len * 2

    if auto_str == ">>>AUTOIT SCRIPT<<<":
        comp = data[off]
        off += 1

        data_size = struct.unpack("<I", data[off:][:4])[0] ^ 0x87BC
        off += 4

        code_size = struct.unpack("<I", data[off:][:4])[0] ^ 0x87BC
        off += 4

        crc = struct.unpack("<I", data[off:][:4])[0] ^ 0xA685
        off += 4

        off += 0x10

        data = decrypt_lame(data[off:][:data_size], 0x2477)
        off += data_size
        if crc == crc_data(data):
            log.debug("CRC data matches")
        else:
            log.error("CRC data mismatch")
            return None

        if comp == 1:
            dec = decompress_ea06(data)
            if not dec:
                return None
            data = dec

        return (off, deassemble_script(data))
    else:
        off += 1
        next_blob = (struct.unpack("<I", data[off:][:4])[0] ^ 0x87BC) + 0x18
        off += 4 + next_blob

    return (off, None)


def parse_all(data: bytes) -> Optional[str]:
    off = 0x28

    while True:
        header = parse_au3_header(data[off:])
        if not header:
            break
        offset, script = header
        off += offset
        if script:
            return script

    return None
