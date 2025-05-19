# SYN Flood & Port Scan Detection Lab 

This project implements a network anomaly detection system using raw socket programming in C. It detects SYN flood attacks and unauthorized port scans by analyzing TCP flags and traffic behavior on the server side.

## 🔍 Objective
- Understand TCP SYN flood and port scanning behavior
- Use raw sockets to craft and capture TCP packets
- Detect SYN floods based on incomplete TCP handshakes
- Detect port scans based on rapid multi-port access from the same source
- Deploy client and server in Docker containers for testing

## 🧰 Tools Used
- C (Raw socket programming)
- Docker (SEED Ubuntu 20.04 VM)
- TCP/IP protocol stack
- Wireshark (for packet capture and validation)

## 📌 Key Features
- **Raw Socket Server:** Listens for TCP packets and parses headers
- **SYN Flood Detection:** Identifies multiple incomplete handshakes
- **Port Scan Detection:** Flags excessive multi-port traffic from a single IP
- **Dockerized Setup:** Easily deploy server and client in isolated containers

## 🛡️ Key Observations
- Proper Docker privilege and root access are required for raw sockets
- Thresholds can be adjusted for tuning detection sensitivity
- Real-time traffic analysis is possible using `recvfrom()` and TCP flag checks


