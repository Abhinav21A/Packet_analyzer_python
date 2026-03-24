# Packet Analyzer

This is a Python conversion of the packet analyzer project, rebuilt in a simpler and interview-friendly structure while keeping the core idea the same: read packets from a PCAP file, parse network layers, and print readable packet insights.

## Features
- Reads classic `.pcap` files
- Parses Ethernet, IPv4, TCP, and UDP headers
- Shows packet-by-packet summary
- Adds lightweight traffic classification
- Adds TCP flow hints
- Shows both hex preview and ASCII payload preview
- Prints end-of-run analytics summary

## Project Structure

```text
Packet_analyzer_python/
├── packet_analyzer/              # Core source code
│   ├── __init__.py
│   ├── pcap_reader.py            # Reads packets from PCAP files
│   ├── packet_parser.py          # Parses packet headers and protocol details
│
├── main.py                       # Entry point of the project
├── generate_test_pcap.py         # Generates sample PCAP test data
├── test_dpi.pcap                 # Sample packet capture file
├── output.pcap                   # Generated/output capture file
├── requirements.txt              # Project dependencies
├── INTERVIEW_GUIDE.txt           # Notes for explaining the project in interviews
└── README.md                     # Project documentation

## How to Run
```bash
python main.py output.pcap
python main.py output.pcap 10
```

## Project Structure
- `main.py`
- `packet_analyzer/pcap_reader.py`
- `packet_analyzer/packet_parser.py`


