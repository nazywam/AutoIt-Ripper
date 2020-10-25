import logging
import struct
from enum import Enum
from typing import Optional, Tuple, Iterator, List

import lief  # type: ignore

from .opcodes import OPCODES
from .utils import BitStream, crc_data, decrypt_lame, decrypt_mt, filetime_to_dt

EA05_MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d41553321")


class AutoItVersion(Enum):
    EA05 = 0
    EA06 = 1


# 10 megabytes
MAX_SCRIPT_SIZE = 10 * 10 ** 6

log = logging.getLogger(__name__)


def u32(data: bytes) -> int:
    return struct.unpack("<I", data[:4])[0]


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
        log.error("Magic mismatch: %s", data[:4])
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


def parse_au3_header_ea05(data: bytes, checksum: int) -> Iterator[Tuple[str, bytes]]:
    off = 0

    while True:
        file_str = decrypt_mt(data[off:][:4], 0x16FA)
        if file_str != b"FILE":
            log.debug("FILE magic mismatch")
            # Asssume that this is the end of the embedded data
            return
            yield

        off += 4
        flag = u32(data[off:]) ^ 0x29BC
        off += 4
        auto_str = decrypt_mt(data[off:][:flag], 0xA25E + flag).decode("utf-8")
        log.debug("Found a new autoit string: %s", auto_str)
        off += flag
        path_len = u32(data[off:]) ^ 0x29AC
        off += 4
        path = decrypt_mt(data[off:][:path_len], 0xF25E + path_len).decode("utf-8")
        log.debug("Found a new path: %s", path)
        off += path_len

        if auto_str == ">>>AUTOIT NO CMDEXECUTE<<<":
            off += 1
            next_blob = (u32(data[off:]) ^ 0x45AA) + 0x18
            off += 4 + next_blob
        else:
            comp = data[off]
            off += 1

            data_size = u32(data[off:]) ^ 0x45AA
            off += 4

            uncompressed_size = u32(data[off:]) ^ 0x45AA  # noqa
            off += 4

            crc = u32(data[off:]) ^ 0xC3D2
            off += 4

            CreationTime_dwHighDateTime = u32(data[off:])
            off += 4

            CreationTime = u32(data[off:])
            off += 4

            LastWriteTime_dwHighDateTime = u32(data[off:])
            off += 4

            LastWriteTime = u32(data[off:])
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
                return
                yield

            if comp == 1:
                dec = decompress(dec_data, AutoItVersion.EA05)
                if not dec:
                    log.error("Error while trying to decompress data")
                    return
                    yield
                dec_data = dec

            if auto_str == ">AUTOIT UNICODE SCRIPT<":
                yield ("script.au3", dec_data.decode("utf-16").encode("utf-8"))
            elif auto_str == ">AUTOIT SCRIPT<":
                yield ("script.au3", dec_data)
            else:
                yield (auto_str, dec_data)


def parse_au3_header_ea06(data: bytes) -> Iterator[Tuple[str, bytes]]:
    off = 0

    while True:
        file_str = decrypt_lame(data[off:][:4], 0x18EE)
        if file_str != b"FILE":
            return None

        off += 4
        flag = u32(data[off:]) ^ 0xADBC
        off += 4
        auto_str = decrypt_lame(data[off:][: flag * 2], 0xB33F + flag).decode("utf-16")
        log.debug("Found a new autoit string: %s", auto_str)
        off += flag * 2
        path_len = u32(data[off:]) ^ 0xF820
        off += 4
        path = decrypt_lame(data[off:][: path_len * 2], 0xF479 + path_len).decode(
            "utf-16"
        )
        log.debug("Found a new path: %s", path)
        off += path_len * 2

        if auto_str == ">>>AUTOIT NO CMDEXECUTE<<<":
            off += 1
            next_blob = (u32(data[off:]) ^ 0x87BC) + 0x18
            off += 4 + next_blob
        else:
            comp = data[off]
            off += 1

            data_size = u32(data[off:]) ^ 0x87BC
            off += 4

            uncompressed_size = u32(data[off:]) ^ 0x87BC  # noqa
            off += 4

            crc = u32(data[off:]) ^ 0xA685
            off += 4

            CreationTime_dwHighDateTime = u32(data[off:])
            off += 4

            CreationTime = u32(data[off:])
            off += 4

            LastWriteTime_dwHighDateTime = u32(data[off:])
            off += 4

            LastWriteTime = u32(data[off:])
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
                return
                yield

            if comp == 1:
                dec = decompress(dec_data, AutoItVersion.EA06)
                if not dec:
                    log.error("Error while trying to decompress data")
                    return
                    yield
                dec_data = dec

            if auto_str == ">>>AUTOIT SCRIPT<<<":
                yield ("script.au3", deassemble_script(dec_data).encode())
            else:
                yield (auto_str, dec_data)


def parse_all(data: bytes, version: AutoItVersion) -> List[Tuple[str, bytes]]:
    checksum = sum(list(data[:16]))
    off = 16

    if version == AutoItVersion.EA05:
        return list(parse_au3_header_ea05(data[off:], checksum))
    elif version == AutoItVersion.EA06:
        return list(parse_au3_header_ea06(data[off:]))
    else:
        raise Exception("Unsupported autoit version %s", version)


def unpack_ea05(binary_data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    if EA05_MAGIC not in binary_data:
        log.error("Couldn't find the location chunk in binary")
        return None

    au_off = binary_data.index(EA05_MAGIC)
    script_data = binary_data[au_off:][20:]
    if script_data[:4] != b"EA05":
        log.error("EA05 magic mismatch")
        return None

    parsed_data = parse_all(script_data[4:], AutoItVersion.EA05)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None

    return parsed_data


def unpack_ea06(binary_data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    pe = lief.parse(raw=list(binary_data))
    if not pe:
        log.error("Failed to parse the input file")
        return None

    if not pe.has_resources:
        log.error("The input file has no resources")
        return None

    script_resource = get_script_resource(pe)
    if script_resource is None or not script_resource.childs:
        log.error("Couldn't find the script resource")
        return None

    script_data = list(script_resource.childs)[0].content
    parsed_data = parse_all(bytes(script_data)[0x18:], AutoItVersion.EA06)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None

    return parsed_data


def extract(data: bytes, version: Optional[AutoItVersion] = None) -> Optional[List[Tuple[str, bytes]]]:
    if version is None:
        log.info("AutoIt version not specified, trying both")
        return unpack_ea05(data) or unpack_ea06(data)
    elif version == AutoItVersion.EA05:
        return unpack_ea05(data)
    elif version == AutoItVersion.EA06:
        return unpack_ea06(data)
    else:
        raise Exception("Unknown version specified, use AutoItVersion or None")
