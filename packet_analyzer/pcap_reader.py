from __future__ import annotations
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional
import os
import struct

@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int

@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int

@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes

class PcapReader:
    def __init__(self) -> None:
        self.file: Optional[BinaryIO] = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self.endian = "<"

    def open(self, filename: str) -> bool:
        if not os.path.exists(filename):
            print(f"Error: file not found -> {filename}")
            return False
        self.file = open(filename, "rb")
        raw = self.file.read(24)
        if len(raw) != 24:
            print("Error: invalid PCAP global header.")
            self.close()
            return False

        magic_le = struct.unpack("<I", raw[:4])[0]
        magic_be = struct.unpack(">I", raw[:4])[0]

        if magic_le == 0xA1B2C3D4:
            self.endian = "<"
            fmt = "<IHHIIII"
        elif magic_be == 0xA1B2C3D4:
            self.endian = ">"
            fmt = ">IHHIIII"
        else:
            print("Error: unsupported PCAP file format.")
            self.close()
            return False

        self.global_header = PcapGlobalHeader(*struct.unpack(fmt, raw))
        return True

    def close(self) -> None:
        if self.file:
            self.file.close()
            self.file = None

    def read_next_packet(self) -> Optional[RawPacket]:
        if not self.file:
            return None

        hdr = self.file.read(16)
        if not hdr:
            return None
        if len(hdr) != 16:
            print("Warning: truncated packet header encountered.")
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.endian}IIII", hdr)
        data = self.file.read(incl_len)
        if len(data) != incl_len:
            print("Warning: truncated packet data encountered.")
            return None

        return RawPacket(PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len), data)

    def __iter__(self) -> Iterator[RawPacket]:
        while True:
            pkt = self.read_next_packet()
            if pkt is None:
                break
            yield pkt
