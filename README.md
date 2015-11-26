SEC-FW-ENGINE
======

## What's is SEC-FW-ENGINE
SEC-FW-ENGINE is a high performance Netwrok Packet Process Engine. It is a universal, flexible,  stable architecture which can be used in IDS, IPS, and other Network Security Monitoring System.

## Architecture

## All features
### Configuration
- Based on CLI Parser(Open Source Software)
- Support Cisco-like CLI commands
- Configuration file load/save

### Packet Decoding
- IPv4, TCP, UDP, ICMPv4
- Ethernet, VLAN
- Protocal inspect plugin supporting

### TCP/IP engine
- L2/L3 Parser
- IP fragment reassemb
- TCP stream session tracking
- TCP steam reassemb
- Flow engine

### Software ACL
- Base on HS Algorithm
- Arbitrary combination of five-tuples + time
- Add/Delete/Show/Modify flexible
  
### System Level Components
- Multi Threading
- Cpu Affinity
- Use of fine grained locking and atomic operations for optimal performance
- High performance memory pool

### Hardware Platform supporting list
- Cavium octeon (base on SE-UM mode of SDK which provide by Linux kernel source code)
- DPDK (Todo...) 

## How to use
