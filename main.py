from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime
from packet_analyzer.pcap_reader import PcapReader
from packet_analyzer.packet_parser import PacketParser

def print_banner() -> None:
    print("=" * 46)
    print("        Packet Analyzer v1.1 (Python)")
    print("=" * 46)

def print_packet_summary(pkt, packet_num: int) -> None:
    ts = datetime.fromtimestamp(pkt.timestamp_sec).strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {ts}.{pkt.timestamp_usec:06d}")

    print("\n[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    print(f"  EtherType:       0x{pkt.ether_type:04x}")

    if pkt.has_ip:
        print(f"\n[IPv{pkt.ip_version}]")
        print(f"  Source IP:       {pkt.src_ip}")
        print(f"  Destination IP:  {pkt.dest_ip}")
        print(f"  Protocol:        {PacketParser.protocol_to_string(pkt.protocol)}")
        print(f"  TTL:             {pkt.ttl}")

    if pkt.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {PacketParser.tcp_flags_to_string(pkt.tcp_flags)}")
        print(f"  Flow Hint:        {pkt.flow_hint}")

    if pkt.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")

    print("\n[Classification]")
    print(f"  Traffic Type:     {pkt.traffic_type}")

    if pkt.payload_length > 0:
        print("\n[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview_len = min(pkt.payload_length, 32)
        hex_preview = " ".join(f"{b:02x}" for b in pkt.payload_data[:preview_len])
        suffix = " ..." if pkt.payload_length > 32 else ""
        print(f"  Hex Preview:   {hex_preview}{suffix}")
        print(f"  ASCII Preview: {PacketParser.ascii_preview(pkt.payload_data)}")

def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze packets from a PCAP file.")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("max_packets", nargs="?", type=int, default=-1, help="Optional limit")
    args = parser.parse_args()

    print_banner()
    reader = PcapReader()
    if not reader.open(args.pcap_file):
        return 1

    total_packets = 0
    parse_errors = 0
    stats = Counter()
    traffic_mix = Counter()
    total_payload_bytes = 0

    for raw in reader:
        total_packets += 1
        parsed = PacketParser.parse(raw)
        if parsed is None:
            print(f"Warning: Failed to parse packet #{total_packets}")
            parse_errors += 1
        else:
            print_packet_summary(parsed, total_packets)
            if parsed.has_ip:
                stats["ip"] += 1
            if parsed.has_tcp:
                stats["tcp"] += 1
            if parsed.has_udp:
                stats["udp"] += 1
            total_payload_bytes += parsed.payload_length
            traffic_mix[parsed.traffic_type] += 1

        if args.max_packets > 0 and total_packets >= args.max_packets:
            print(f"\n(Stopped after {args.max_packets} packets)")
            break

    reader.close()

    print("\n" + "=" * 46)
    print("Summary")
    print(f"  Total packets read:   {total_packets}")
    print(f"  Parse errors:         {parse_errors}")
    print(f"  IP packets:           {stats['ip']}")
    print(f"  TCP packets:          {stats['tcp']}")
    print(f"  UDP packets:          {stats['udp']}")
    print(f"  Payload bytes seen:   {total_payload_bytes}")
    print("  Traffic mix:")
    if traffic_mix:
        for name, count in traffic_mix.most_common():
            print(f"    - {name}: {count}")
    else:
        print("    - None")
    print("=" * 46)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
