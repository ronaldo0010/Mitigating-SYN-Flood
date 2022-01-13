## TCP packet construction
Header contains 
* Source and destination addresses.
* SYN (synchronize) and ACK (acknowledge) flags.
* Other valuable information (see figure below)

![](https://cdn.kastatic.org/ka-perseus-images/9a4a79816965be53e1071cf6b0e2991cb4d170ca.svg)

## TCP establish connection
* Client sends SYN.
* Server receives and responds with SYN ACK.
* Client receives and responds with ACK. 

![](https://cdn.kastatic.org/ka-perseus-images/d09f9d37ff2a2deb21a8822f8c99ba6b86319f0b.svg)

This process is the 3-way handshake to establish a Client-Server connection [Fox, 2019]

## TCP SYN-Attack
* Malicious client sends 1 part of 3-way handshake, SYN packet.
* The server notices this flow, allocates resources for the connection
* The server acknowledges by sending a TCP SYN ACK packet and continues waiting for the client's response.
* The client continues sending these TCP/IP requests to establish various TCP connections.
* Indefinitely, the server can run out of resources allocated to these connections - resulting in deadlock, and possible valid TCP connections being dropped.
  [Scholz, 2020]

## Traditional SYN-Attack Mitigation Stragtegies
### Naive Strategies
* Increased Server backlog
  - Scaling the capacity of TCP stack storage.
* Reduced SYN timer
  - Decrease the time allowed between sending SYN-ACK and waiting to receive ACK.
* Overwriting half-opened TCP Stack entries
  - Replace oldest half-opened connection with incoming SYN packet 

These methods are proven to be ineffective [rfc4987, 2007] since the attacker could easily linearily scale the frequency of SYN-packets sent.

### More Reliable Strategies
* SYN-cookies
  - Uses a hidden cryptographic hash function to compete and store a secrete key. 
  - Function of the timestamp and source- and destination address of the received SYN-packet.
  - Only adds an entry to the TCP stack once the final ACK is received and corresponds with the hash value stored.
  - Finally opens connection between client and server
  [A10 Networks, 2019]
* Firewall & Proxy Filtering
  - Ensures that only legitimate connections are established with the end user/server
  -  By handling the 3-way handshake on the firewall side and passing the connection via proxy to server [rfc4987, 2007].
  
# Newly added section
## P4 programmable data plane
Programmable data planes (PDP) enables network operators with a tool to change/modify the purpose of a network switch. 

Traditionally a SDN would handle packet forwarding but with a PDP the hardware gets utilized for this purpose with a significant increase in performance [Jacobs, 2019].

### PPPP - Alien sounds or revolutionary developer tool?
P4 is a programming language for controlling packet forwarding planes in network devices. It is open source and maintained by P4 Language Consortium (https://p4.org/) and acronym PPPP stands for Programming Protocol-Independent Packet Processors.

### Putting the pro in programmable - advantages of PDP
* Check and modify packet headers s.t custom requirements [Gao, 2021].
* Encapsulate and forward packets with a non-IP protocol defined via an IP network [Jacobs, 2019].
* Utilize hardware speeds (100 Gb/s) to perform tasks.
* Load balancing, limiting ingress (?) speeds, comms with other devices via controller [Geo, 2021].
* More Cost-effective (time and monetary) than purpose spesific chips.
* Adaptable for new application scenarios.

### Limitations of PDP's
  * Although PDP is capable of doing computions it's at the expensive of throughput
  * PDP's only supports simple arithmetic operations thus precalculations and/or approximations need to be loaded in a match-table or registers.
  * Lacks correctness verification - developers writing code for forwarding behavior on the data plane of a pdp is not as knowledgeable as the equipment manufacturer

### Note worthy mentions - Use cases for PDP's
* Traffic Measurement and -Engineering
  - Congestion detection
  - Active queue management
  - Load balancing
* Routing and Forwarding
  - L4 load balancing
  - Source routing
  - Named data networking
* Advanced Network Support
  - 5G networks
  - IoT
  - Time-sensitive networks  
* Network Security
  - Instrusion detection
  - Encryption
  - DDos attack mitigation [project focus]
  - Topology scrammingling
* Network Accelerated Computing
  - Machine learning
  - Deep [packet (?)] detection

[Geo, 2021]
  

## P4 SYN-Flood attack Mitigation Stragtegies
todo


## Sources
[A Review of P4 Programmable Data Planes for Network Security, Ya Geo, Zhenling Wang](https://downloads.hindawi.com/journals/misy/2021/1257046.pdf)

[Me Love (SYN-)Cookies: SYN Flood Mitigation in Programmable Data Planes, Scholz Et Al.](https://arxiv.org/pdf/2003.03221.pdf)

[TCP SYN Flooding Attacks and Common Mitigations, RFC4987](https://datatracker.ietf.org/doc/html/rfc4987)

[Transmission Control Protocol (TCP), Pamela Fox](https://www.khanacademy.org/computing/computers-and-internet/xcae6f4a7ff015e7d:the-internet/xcae6f4a7ff015e7d:transporting-packets/a/transmission-control-protocol--tcp)

[What are Syn Cookies and how are they used?, A10 Networks](https://youtu.be/ymttSrEo0R0)


[What is a programmable data plane and where does P4 fit in?, David Jacobs](https://www.techtarget.com/searchnetworking/answer/What-is-a-programmable-data-plane-and-where-does-P4-fit-in)

