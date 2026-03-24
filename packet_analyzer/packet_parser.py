from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import socket
import struct

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_data: bytes = b""
    traffic_type: str = "Unknown"
    flow_hint: str = "N/A"

class PacketParser:
    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac)

    @staticmethod
    def protocol_to_string(proto: int) -> str:
        return {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(proto, f"Other({proto})")

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        names = []
        if flags & 0x01: names.append("FIN")
        if flags & 0x02: names.append("SYN")
        if flags & 0x04: names.append("RST")
        if flags & 0x08: names.append("PSH")
        if flags & 0x10: names.append("ACK")
        if flags & 0x20: names.append("URG")
        return "|".join(names) if names else "None"

    @staticmethod
    def classify_traffic(parsed: ParsedPacket) -> str:
        if not parsed.has_ip:
            return "Non-IP"
        ports = {parsed.src_port, parsed.dest_port}
        if 80 in ports: return "HTTP"
        if 443 in ports: return "HTTPS/TLS"
        if 53 in ports: return "DNS"
        if 22 in ports: return "SSH"
        if parsed.has_tcp: return "TCP-Other"
        if parsed.has_udp: return "UDP-Other"
        return "IP-Other"

    @staticmethod
    def flow_hint(parsed: ParsedPacket) -> str:
        if not parsed.has_tcp:
            return "N/A"
        flags = parsed.tcp_flags
        syn, ack = bool(flags & 0x02), bool(flags & 0x10)
        fin, rst, psh = bool(flags & 0x01), bool(flags & 0x04), bool(flags & 0x08)
        if syn and not ack: return "Handshake (SYN)"
        if syn and ack: return "Handshake (SYN-ACK)"
        if rst: return "Connection Reset"
        if fin: return "Connection Close"
        if psh: return "Data Push"
        if ack: return "Established Flow"
        return "TCP Activity"

    @staticmethod
    def ascii_preview(data: bytes, max_len: int = 32) -> str:
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:max_len])

    @staticmethod
    def parse(raw_packet) -> Optional[ParsedPacket]:
        data = raw_packet.data
        if len(data) < ETH_HEADER_LEN:
            return None

        parsed = ParsedPacket(timestamp_sec=raw_packet.header.ts_sec, timestamp_usec=raw_packet.header.ts_usec)
        dest_mac, src_mac, ether_type = struct.unpack("!6s6sH", data[:ETH_HEADER_LEN])
        parsed.dest_mac = PacketParser.mac_to_string(dest_mac)
        parsed.src_mac = PacketParser.mac_to_string(src_mac)
        parsed.ether_type = ether_type

        offset = ETH_HEADER_LEN
        if ether_type != ETHERTYPE_IPV4:
            parsed.traffic_type = "Non-IP"
            return parsed

        if len(data) < offset + 20:
            return None

        version_ihl = data[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or len(data) < offset + ihl:
            return None

        ip_header = data[offset:offset + ihl]
        unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header[:20])
        parsed.has_ip = True
        parsed.ip_version = version
        parsed.ttl = unpacked[5]
        parsed.protocol = unpacked[6]
        parsed.src_ip = socket.inet_ntoa(unpacked[8])
        parsed.dest_ip = socket.inet_ntoa(unpacked[9])
        offset += ihl

        if parsed.protocol == PROTO_TCP:
            if len(data) < offset + 20:
                return None
            tcp_base = data[offset:offset + 20]
            src_port, dest_port, seq, ack, data_offset_reserved, flags, *_ = struct.unpack("!HHLLBBHHH", tcp_base)
            tcp_header_len = ((data_offset_reserved >> 4) & 0x0F) * 4
            if len(data) < offset + tcp_header_len:
                return None
            parsed.has_tcp = True
            parsed.src_port = src_port
            parsed.dest_port = dest_port
            parsed.seq_number = seq
            parsed.ack_number = ack
            parsed.tcp_flags = flags
            offset += tcp_header_len
        elif parsed.protocol == PROTO_UDP:
            if len(data) < offset + 8:
                return None
            src_port, dest_port, _, _ = struct.unpack("!HHHH", data[offset:offset + 8])
            parsed.has_udp = True
            parsed.src_port = src_port
            parsed.dest_port = dest_port
            offset += 8

        parsed.payload_data = data[offset:] if offset < len(data) else b""
        parsed.payload_length = len(parsed.payload_data)
        parsed.traffic_type = PacketParser.classify_traffic(parsed)
        parsed.flow_hint = PacketParser.flow_hint(parsed)
        return parsed
