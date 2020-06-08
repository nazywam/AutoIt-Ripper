import logging
import struct
from enum import Enum
from typing import Optional, Tuple

import lief  # type: ignore

from opcodes import OPCODES
from utils import BitStream, crc_data, decrypt_lame, decrypt_mt, filetime_to_dt

EA05_MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d41553321")


class AutoItVersion(Enum):
    EA05 = 0
    EA06 = 1


# 10 megabytes
MAX_SCRIPT_SIZE = 10 * 10 ** 6

log = logging.getLogger(__name__)


def get_script_resource(pe: lief.PE) -> Optional[lief.PE.ResourceDirectory]:
    for child in pe.resources.childs:
        for grandchild in child.childs:
            if grandchild.has_name and grandchild.name == "SCRIPT":
                return grandchild
    return None


def decompress(data: bytes, version: AutoItVersion) -> Optional[bytes]:
    if data[:4] == b"EA05" and version == AutoItVersion.EA05:
        pass
    elif data[:4] == b"EA06" and version == AutoItVersion.EA06:
        pass
    else:
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


def deassemble_script(script_data: bytes) -> str:
    section_num = struct.unpack("<I", script_data[:4])[0]
    section_index = 0
    offset = 4

    out = ""
    while section_index < section_num:
        opcode = script_data[offset]
        if opcode in OPCODES:
            add, off = OPCODES[opcode](script_data[offset:])
        elif opcode == 0x7F:
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


def parse_au3_header_ea05(
    data: bytes, checksum: int
) -> Optional[Tuple[int, Optional[str]]]:
    off = 0
    file_str = decrypt_mt(data[off:][:4], 0x16FA)
    if file_str != b"FILE":
        return None

    off += 4
    flag = struct.unpack("<I", data[off:][:4])[0] ^ 0x29BC
    off += 4
    auto_str = decrypt_mt(data[off:][:flag], 0xA25E + flag).decode("utf-8")
    log.debug("Found a new autoit string: %s", auto_str)
    off += flag
    path_len = struct.unpack("<I", data[off:][:4])[0] ^ 0x29AC
    off += 4
    path = decrypt_mt(data[off:][:path_len], 0xF25E + path_len).decode("utf-8")
    log.debug("Found a new path: %s", path)
    off += path_len

    if auto_str == ">AUTOIT UNICODE SCRIPT<":
        comp = data[off]
        off += 1

        data_size = struct.unpack("<I", data[off:][:4])[0] ^ 0x45AA
        off += 4

        uncompressed_size = (
            struct.unpack("<I", data[off:][:4])[0] ^ 0x45AA
        )  # not used anywhere?
        off += 4

        crc = struct.unpack("<I", data[off:][:4])[0] ^ 0xC3D2
        off += 4

        CreationTime_dwHighDateTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        CreationTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        LastWriteTime_dwHighDateTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        LastWriteTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        creation_time = filetime_to_dt(
            (CreationTime_dwHighDateTime << 32) + CreationTime
        )
        last_write_time = filetime_to_dt(
            (LastWriteTime_dwHighDateTime << 32) + LastWriteTime
        )

        log.debug(f"File creation time: {creation_time}")
        log.debug(f"File last write time: {last_write_time}")

        dec_data = decrypt_mt(data[off:][:data_size], checksum + 0x22AF)
        off += data_size
        if crc == crc_data(dec_data):
            log.debug("CRC data matches")
        else:
            log.error("CRC data mismatch")
            return None

        if comp == 1:
            dec = decompress(dec_data, AutoItVersion.EA05)
            if not dec:
                return None
            dec_data = dec

        return (off, dec_data.decode("utf-16"))
    else:
        off += 1
        next_blob = (struct.unpack("<I", data[off:][:4])[0] ^ 0x45AA) + 0x18
        off += 4 + next_blob

    return (off, None)


def parse_au3_header_ea06(data: bytes) -> Optional[Tuple[int, Optional[str]]]:
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

        CreationTime_dwHighDateTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        CreationTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        LastWriteTime_dwHighDateTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        LastWriteTime = struct.unpack("<I", data[off:][:4])[0]
        off += 4

        creation_time = filetime_to_dt(
            (CreationTime_dwHighDateTime << 32) + CreationTime
        )
        last_write_time = filetime_to_dt(
            (LastWriteTime_dwHighDateTime << 32) + LastWriteTime
        )

        log.debug(f"File creation time: {creation_time}")
        log.debug(f"File last write time: {last_write_time}")

        dec_data = decrypt_lame(data[off:][:data_size], 0x2477)
        off += data_size
        if crc == crc_data(dec_data):
            log.debug("CRC data matches")
        else:
            log.error("CRC data mismatch")
            return None

        if comp == 1:
            dec = decompress(dec_data, AutoItVersion.EA06)
            if not dec:
                return None
            dec_data = dec

        return (off, deassemble_script(dec_data))
    else:
        off += 1
        next_blob = (struct.unpack("<I", data[off:][:4])[0] ^ 0x87BC) + 0x18
        off += 4 + next_blob

    return (off, None)


def parse_all(data: bytes, version: AutoItVersion) -> Optional[str]:
    checksum = sum(list(data[:16]))
    off = 16

    while True:
        if version == AutoItVersion.EA05:
            header = parse_au3_header_ea05(data[off:], checksum)
        elif version == AutoItVersion.EA06:
            header = parse_au3_header_ea06(data[off:])
        else:
            raise Exception("Unsupported autoit version %s", version)
        if not header:
            break
        offset, script = header
        off += offset
        if script:
            return script

    log.error("Couldn't find any au3 headers")
    return None


def unpack_ea05(filename: str) -> Optional[str]:
    with open(filename, "rb") as f:
        binary_data = f.read()

    if EA05_MAGIC not in binary_data:
        log.error("Couldn't find the location chunk in binary")
        return None

    au_off = binary_data.index(EA05_MAGIC)
    script_data = binary_data[au_off:][20:]
    if script_data[:4] != b"EA05":
        log.error("EA05 magic mismatch")
        return None

    parsed_data = parse_all(bytes(script_data)[4:], AutoItVersion.EA05)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None

    return parsed_data


def unpack_ea06(filename: str) -> Optional[str]:
    pe = lief.parse(filename)
    if not pe:
        log.error("Failed to parse the input file")
        return None

    if not pe.has_resources:
        log.error("The input file has no resources")
        return None

    script_resource = get_script_resource(pe)
    if script_resource is None:
        log.error("Couldn't find the script resource")
        return None

    script_data = list(script_resource.childs)[0].content
    parsed_data = parse_all(bytes(script_data)[0x18:], AutoItVersion.EA06)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None

    return parsed_data
