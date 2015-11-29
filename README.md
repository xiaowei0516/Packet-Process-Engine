PPE(Packet Process Engine)
======

## What is PPE
Packet Process Engine is a high performance Netwrok Packet Process Engine. It is a universal, flexible,  stable architecture which can be used in IDS, IPS, and other Network Security Monitoring System.

## Architecture
1. Linux Userspace daemon
2. ManagePlane and Dataplane isolation
3. Dataplane Realtime Multiple-Threads - Run to End mode

## All features
### Configuration
- Based on CLI Parser(Open Source Software)
- Support Cisco-like CLI commands
- Configuration file load/save
- Multiple Users support

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
- Network Packet Zero-Copy
- Multi Threading
- Cpu Affinity
- Use of fine grained locking and atomic operations for optimal performance
- High performance memory pool

### Hardware Platform supporting list
- Cavium octeon (base on SE-UM mode of SDK which provide by Linux kernel source code)
- DPDK (Todo...) 

## How to use
1. Download source code

2. Setup platform environment

3. Complie
```bash
#cd code root path
#./build.sh             //ManagePlane and Dataplane full compile
#./build.sh mgrplane    //ManagePlane compile 
#./build.sh dataplane   //Dataplane compile
#./build.sh clean       //Compile clean
```

4. Run
```bash
#cd ./bin
#./startup.sh
#./srv
#schedtool –a 0x2 –e ./secd-linux_64
#./cli
```

## Contributors
PPE is designed and implemented by @Roy Luo. For more information about the author, please visit: [http://royluo.org/about](http://royluo.org/about)
