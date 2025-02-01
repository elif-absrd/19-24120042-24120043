## Packet Sniffer and Analysis Assignment

This repository contains the code and instructions for an assignment focused on analyzing network traffic from a `.pcap` file using Kali Linux in a live boot environment. The assignment involves compiling and running a C++ sniffer program, replaying packets using `tcpreplay`, and analyzing packet sizes with Python libraries.

## Environment Setup

- **Operating System:** Kali Linux (Live Boot via Rufus)
- **Languages and Tools Used:**
  - **C++** for packet sniffing and analysis.
  - **tcpreplay** to replay `.pcap` files.
  - **Python** with `pandas` and `matplotlib` to visualize packet data.

## Steps to Run the Project

### 1. Setup Kali Linux Live Boot
- Create a live boot environment of Kali Linux using Rufus.
- Boot into Kali Linux using your USB drive.

### 2. Compile the C++ Sniffer Program
- The C++ program `sniffer.cpp` captures and analyzes packets from a network interface.
- To compile the C++ program, run the following command in the terminal:

```bash
g++ sniffer.cpp -o sniffer -lpcap
```

### 3. Run the C++ Sniffer Program
- After compiling, run the program with the following command to start packet sniffing:

```bash
./sniffer
```

### 4. Replay the .pcap File Using tcpreplay
- To replay the `.pcap` file for analysis, use the `tcpreplay` tool with this command:

```bash
sudo tcpreplay -i lo --mbps=100 1.pcap
```
This will replay the packet capture (`1.pcap`) on the loopback interface at a speed of 100 Mbps.

### 5. Setup Python Environment for Data Analysis
- Create a virtual environment for Python and install required libraries:

```bash
python -m venv venv
source venv/bin/activate  # For Linux/MacOS
venv\Scripts\activate     # For Windows
pip install pandas matplotlib
```

### 6. Analyze Packet Data
- Using `pandas` and `matplotlib`, create a histogram to analyze and visualize packet sizes. The Python code processes the packet data and generates visualizations.

### 7. Analyze Application Layer Protocol
- The `tcpreplay` tool can also be used to identify application layer protocols in the `.pcap` file.

## Conclusion
This assignment demonstrates how to capture, analyze, and visualize network traffic data from a `.pcap` file using C++, `tcpreplay`, and Python. The analysis includes packet size distribution and protocol identification, providing valuable insights into network traffic.

## Files in this Repository
- **sniffer.cpp:** C++ source code for packet sniffing.
- **1.pcap:** Sample packet capture file for replay and analysis.
- **analyze_packets.py:** Python script for analyzing packet sizes and visualizing them with a histogram.

## Prerequisites
- Kali Linux Live Boot Environment.
- `tcpreplay`: For replaying `.pcap` files.
- `libpcap-dev`: To compile the C++ program to run with pcap file.
- Python 3: For running the analysis script.



