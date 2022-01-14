## TCP packet construction
Header contains 
* Source and destination addresses.
* SYN (synchronize) and ACK (acknowledge) flags.
* Other valuable information (see figure below).

![](https://cdn.kastatic.org/ka-perseus-images/9a4a79816965be53e1071cf6b0e2991cb4d170ca.svg)

## TCP establish connection
* Client sends SYN.
* Server receives and responds with SYN ACK.
* Client receives and responds with ACK. 

![](https://cdn.kastatic.org/ka-perseus-images/d09f9d37ff2a2deb21a8822f8c99ba6b86319f0b.svg)

This process is the 3-way handshake to establish a Client-Server connection [Fox, 2019].

## TCP SYN-Attack
* Malicious client sends 1 part of 3-way handshake, SYN segment.
* The server notices this flow, allocates resources for the connection
* The server acknowledges by sending a TCP SYN ACK segment and continues waiting for the client's response.
* The client continues sending these TCP/IP segments to establish various TCP connections.
* Indefinitely, the server can run out of resources allocated to these connections - resulting in deadlock, and possible valid TCP connections being dropped.
  [Scholz, 2020]

## Traditional SYN-Attack Mitigation Stragtegies
### Naive Strategies
* Increased Server backlog
  * Scaling the capacity of TCP stack storage.
* Reduced SYN timer
  * Decrease the time allowed between sending SYN-ACK and waiting to receive ACK.
* Overwriting half-opened TCP Stack entries
  * Replace oldest half-opened connection with incoming SYN segment. 

These methods are proven to be ineffective [rfc4987, 2007] since the attacker could easily linearily scale the frequency of SYN-segments sent.

### More Reliable Strategies
* SYN-cookies
  * Uses a hidden cryptographic hash function to compete and store a secrete key. 
  * Function of the timestamp and source- and destination address of the received SYN-segment.
  * Only adds an entry to the TCP stack once the final ACK is received and corresponds with the hash value stored.
  * Finally opens connection between client and server.
  [A10 Networks, 2019]
* Firewall & Proxy Filtering
  * Ensures that only legitimate connections are established with the end user/server.
  *  By handling the 3-way handshake on the firewall side and passing the connection via proxy to server [rfc4987, 2007].
  

## P4 programmable data plane
Programmable data planes (PDP) enables network operators with a tool to change/modify the purpose of a network switch. 

Traditionally a SDN would handle packet forwarding but with a PDP the hardware gets utilized for this purpose with a significant increase in performance [Jacobs, 2019].

### PPPP - Alien communication or revolutionary developer tool?
The acronym PPPP stands for Programming Protocol-Independent Packet Processors. P4 is a programming language for controlling packet forwarding planes in network devices. It is open source and maintained by the P4 Language Consortium (https://p4.org/).

### Putting the pro in programmable - advantages of PDP
* Check and modify packet headers s.t custom requirements [Gao, 2021].
* Encapsulate and forward packets with a non-IP protocol defined via an IP network [Jacobs, 2019].
* Utilize hardware speeds (100 Gb/s) to perform tasks.
* Load balancing, limiting ingress (?) speeds, comms with other devices via controller [Geo, 2021].
* More Cost-effective (time and monetary) than purpose spesific chips.
* Adaptable for new application scenarios.

### Limitations of PDP's
  * Although PDP is capable of doing computions it's at the expensive of throughput.
  * PDP's only supports simple arithmetic operations thus precalculations and/or approximations need to be loaded in a match-table or registers.
  * Lacks correctness verification - developers writing code for forwarding behavior on the data plane of a pdp is not as knowledgeable as the equipment manufacturer.

### Note worthy mentions - Use cases for PDP's
* Traffic Measurement and -Engineering
  * Congestion detection
  * Active queue management
  * Load balancing
* Routing and Forwarding
  * L4 load balancing
  * Source routing
  * Named data networking
* Advanced Network Support
  * 5G networks
  * IoT
  * Time-sensitive networks  
* Network Security
  * Instrusion detection
  * Encryption
  * DDos attack mitigation [project focus]
  * Topology scrammingling
* Network Accelerated Computing
  * Machine learning
  * Deep [packet (?)] detection

[Geo, 2021]

## P4 SYN-Flood attack Mitigation Stragtegies
The concept of a SYN-Proxy is based on the idea of intercepting potentially harmful traffic before it reaches the server. 
In addition, installing a dedicated SYN-Proxy allows the server to save resources by not handling attack mitigations itself.

According to [Scholz, 2020] only the following strategies provide adequate protection and high service quality: 
* SYN-Cookie.
* SYN-Auth with cryptographic hash.
* SYN-Auth without cryptographic hash.

### SYN-Cookie 
* Secured with a cryptographic hash bound to the flow.
* expects a appropriate final segment of TCP handshake.
* On Completetion connection is forwarded to the aplication.

![text here](assets/SYN-cookie.png)

Fig. above shows SYN-Cookie message exchange strategy.
  
### SYN-Authentication
* Whitelists the client or client's subnet on completetion.
* Accepts future connections from source or subnet.
* Can be combined with a cryptographic hash.
  
![text here](assets/Auth_cookie.png)

Fig. above shows the simplicity of SYN-Authentication message exchange strategy.

## The Setup
In the study [Scholz, 2020], the stack used to find if is possible to mitigate SYN-attacks with a programmable data plane is described below.

### Software Packet Processing Prototype
* libmoon for SYN proxy prototype in software targeting Commercial Off The Shelf hardware.
  * Powerful and easy-to-use scripting on top of DPDK's packet handling.
  * Proxy runsas userspace program.
  * TCP handshake done by proxy application.
  * Libmoon receive and process packet in batches.
* Hash function
  * Peudo-crytographic SipHash function for cookies and hashmap
  * SipHash can be integrated with programmable software and hardware dataplanes. [Found here](https://www.net.in.tum.de/fileadmin/bibtex/publications/papers/2019-P4-workshop-hashing.pdf).
* Connection State Tracking
  * Garbage collection with second chance page replacement algorithm.
  * Each state extends two bits. If neither are in a set state, entry is inactive and removed.
* SYN-Authentication
  * Fixed size bitmap as Data Structure (DS) for whitelist.
  * ForEach, two bits used for second-chance page replacement algorithm (total of 1GB for entire IPv4 address space).
  * IPv6 whitelisting based on subnet or hash-based DS.
* SYN-Cookies
  * Two hash maps (`active` and `history`) in conjunction
  * `history` replace is periodically deleted and replace by an `active` map, and new empty active hash map is initialized.
  * 2-phase lookup - First `active` map is checked. 
  * If entry exists it is returned. 
  * Else same lookup is done in `history` map and entry is copied to `active` and employing the second chance mechanism. 
  * Else if no entry is found the connection is assumed to not exist. 
  * Inserts are exclusive to `active` map. 
* Optimizations
  * Offloading feature of NIC used for checksum calculation.
  * ForEach TCP packet received only one ation is performed resulting in one outgoing packet.
  
### Programmable Data Plane Prototype

### Results
Summary of the results obtained by [Scholz, 2020].


![text here](assets/cookie-v-auth.png)

Table shows how SYN-Cookie and SYN-Auth compares in a proxy setup. 
* Both strategies have differences w.r.t packet modifications, transparency and Option support.
* More memory required for SYN-cookie than SYN-auth, 32 bits to 2 bits.
* Due to the 3-way handshake design, ACK segment cannot be differentiated from third segment of handshake, proxy has to check every segment against whitelist. 

## Conclusion 
From [Scholz, 2020](https://arxiv.org/pdf/2003.03221.pdf), We conclude that effective and efficient SYN flood mititation on modern data planes is possible. 
SYN-cookies and SYN-auth perform equally well, moreover the simplicity of the SYN-auth implementation makes it a more attractive solution. However, a limiting fator this solution is finding a suitable cryptographic hash function but could be solved thanks to recent developments in hash operations being implemented in hardware - like demonstrated by Bitcoin. This would allow for powerful data plane centric SYN-Flood mitigation. 


## Sources
[A Review of P4 Programmable Data Planes for Network Security, Ya Geo, Zhenling Wang](https://downloads.hindawi.com/journals/misy/2021/1257046.pdf)

[Me Love (SYN-)Cookies: SYN Flood Mitigation in Programmable Data Planes, Scholz Et Al.](https://arxiv.org/pdf/2003.03221.pdf)

[TCP SYN Flooding Attacks and Common Mitigations, RFC4987](https://datatracker.ietf.org/doc/html/rfc4987)

[Transmission Control Protocol (TCP), Pamela Fox](https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp)

[What are Syn Cookies and how are they used?, A10 Networks](https://youtu.be/ymttSrEo0R0)

[What is a programmable data plane and where does P4 fit in?, David Jacobs](https://www.techtarget.com/searchnetworking/answer/What-is-a-programmable-data-plane-and-where-does-P4-fit-in)

