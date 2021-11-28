import logging
from typing import Iterator, List, Optional, Tuple, Union

import pefile  # type: ignore

from .decompress import decompress
from .opcodes import deassemble_script
from .utils import (
    AutoItVersion,
    ByteStream,
    EA05Decryptor,
    EA06Decryptor,
    crc_data,
    filetime_to_dt,
)

log = logging.getLogger(__name__)


EA05_MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d41553321")


def find_root_dir(pe: pefile.PE, RT_Name: str) -> Optional[pefile.ResourceDirData]:
    dir_entries = [
        entry
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
        if entry.id == pefile.RESOURCE_TYPE[RT_Name]
    ]
    if len(dir_entries) == 1:
        return dir_entries[0].directory
    elif len(dir_entries) == 0:
        log.error("Couldn't find any appropiate PE resource directory")
        return None
    else:
        log.error("Found multiple PE resource directories, inspect the binary manually")
        return None


def get_script_resource(pe: pefile.PE) -> Optional[pefile.Structure]:
    root_dirs = find_root_dir(pe=pe, RT_Name="RT_RCDATA")
    if not root_dirs:
        return None

    for entry in root_dirs.entries:
        if entry.name and entry.name.string == b"SCRIPT":
            return entry.directory.entries[0].data.struct
    return None


def read_string(
    stream: ByteStream,
    decryptor: Union[EA05Decryptor, EA06Decryptor],
    keys: Tuple[int, int],
) -> str:
    length = stream.u32() ^ keys[0]
    enc_key = length + keys[1]

    if decryptor.au3_Unicode:
        length <<= 1
        encoding = "utf-16"
    else:
        encoding = "utf-8"

    return decryptor.decrypt(stream.get_bytes(length), enc_key).decode(encoding)


def parse_au3_header(
    stream: ByteStream, checksum: int, decryptor: Union[EA05Decryptor, EA06Decryptor]
) -> Iterator[Tuple[str, bytes]]:

    while True:
        file_str = decryptor.decrypt(stream.get_bytes(4), decryptor.au3_ResType)
        if file_str != b"FILE":
            log.debug("FILE magic mismatch")
            # Asssume that this is the end of the embedded data
            return
            yield

        au3_ResSubType = read_string(stream, decryptor, decryptor.au3_ResSubType)
        au3_ResName = read_string(stream, decryptor, decryptor.au3_ResName)
        log.debug("Found a new autoit string: %s", au3_ResSubType)
        log.debug("Found a new path: %s", au3_ResName)

        if au3_ResSubType == ">>>AUTOIT NO CMDEXECUTE<<<":
            stream.skip_bytes(num=1)
            next_blob = (stream.u32() ^ decryptor.au3_ResSize) + 0x18
            stream.skip_bytes(num=next_blob)  # uncompressed_size, crc, CreationTime_64
        else:
            au3_ResIsCompressed = stream.u8()
            au3_ResSizeCompressed = stream.u32() ^ decryptor.au3_ResSize
            au3_ResSize = stream.u32() ^ decryptor.au3_ResSize
            au3_ResCrcCompressed = stream.u32() ^ decryptor.au3_ResCrcCompressed

            CreationTime = (stream.u32() << 32) | stream.u32()
            LastWriteTime = (stream.u32() << 32) | stream.u32()

            creation_time_dt = filetime_to_dt(CreationTime)
            last_write_time_dt = filetime_to_dt(LastWriteTime)

            log.debug(f"File creation time: {creation_time_dt}")
            log.debug(f"File last write time: {last_write_time_dt}")

            dec_data = decryptor.decrypt(
                stream.get_bytes(au3_ResSizeCompressed),
                checksum + decryptor.au3_ResContent,
            )
            if au3_ResCrcCompressed == crc_data(dec_data):
                log.debug("CRC data matches")
            else:
                log.error("CRC data mismatch")
                return
                yield

            if au3_ResIsCompressed == 1:
                dec = decompress(ByteStream(dec_data))
                if not dec:
                    log.error("Error while trying to decompress data")
                    return
                    yield
                dec_data = dec

            if au3_ResSubType == ">>>AUTOIT SCRIPT<<<":
                yield ("script.au3", deassemble_script(dec_data).encode())
            elif au3_ResSubType == ">AUTOIT UNICODE SCRIPT<":
                yield ("script.au3", dec_data.decode("utf-16").encode())
            elif au3_ResSubType == ">AUTOIT SCRIPT<":
                yield ("script.au3", dec_data)
            else:
                yield (au3_ResSubType, dec_data)


def parse_all(stream: ByteStream, version: AutoItVersion) -> List[Tuple[str, bytes]]:
    checksum = sum(list(stream.get_bytes(16)))

    if version == AutoItVersion.EA05:
        return list(
            parse_au3_header(
                stream=stream, checksum=checksum, decryptor=EA05Decryptor()
            )
        )
    elif version == AutoItVersion.EA06:
        return list(
            parse_au3_header(stream=stream, checksum=0, decryptor=EA06Decryptor())
        )
    else:
        raise Exception("Unsupported autoit version %s", version)


def unpack_ea05(binary_data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    if EA05_MAGIC not in binary_data:
        log.error("Couldn't find the location chunk in binary")
        return None

    au_off = binary_data.index(EA05_MAGIC)
    stream = ByteStream(binary_data[au_off + 20:])

    if stream.get_bytes(4) != b"EA05":
        log.error("EA05 magic mismatch")
        return None

    parsed_data = parse_all(stream, AutoItVersion.EA05)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None

    return parsed_data


def unpack_ea06(binary_data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    pe = pefile.PE(data=binary_data, fast_load=True)
    if not pe:
        log.error("Failed to parse the input file")
        return None

    pe.parse_data_directories()
    if not pe.DIRECTORY_ENTRY_RESOURCE:
        log.error("The input file has no resources")
        return None

    script_resource = get_script_resource(pe)
    if script_resource is None:
        log.error("Couldn't find the script resource")
        return None

    data_rva = script_resource.OffsetToData
    data_size = script_resource.Size
    script_data = pe.get_memory_mapped_image()[data_rva: data_rva + data_size]

    stream = ByteStream(bytes(script_data)[0x18:])
    parsed_data = parse_all(stream, AutoItVersion.EA06)
    if not parsed_data:
        log.error("Couldn't decode the autoit script")
        return None
    return parsed_data


def extract(
    data: bytes, version: Optional[AutoItVersion] = None
) -> Optional[List[Tuple[str, bytes]]]:
    if version is None:
        log.info("AutoIt version not specified, trying both")
        return unpack_ea05(data) or unpack_ea06(data)
    elif version == AutoItVersion.EA05:
        return unpack_ea05(data)
    elif version == AutoItVersion.EA06:
        return unpack_ea06(data)
    else:
        raise Exception("Unknown version specified, use AutoItVersion or None")
