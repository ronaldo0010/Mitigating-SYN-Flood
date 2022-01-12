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

This process is the 3-way handshaketo establish a Client-Server connection.

## TCP SYN Attack
* Malicious client sends 1 part of 3-way handshake, SYN packet.
* The server notices this flow, allocates resources for the connection
* The server acknowledges by sending a TCP SYN ACK packet and continues waiting for the client's response.
* The client continues sending these TCP/IP requests to establish various TCP connections.
* Indefinitely, the server can run out of resources allocated for these connections - resulting in segfaults or deadlocks.

## Traditional SYN Attack Mitigation Stragtegies
### Naive Strategies
* Filtering 
* Increased backlog
* Reduced timer 
* Overwriting half open TCB entries 

### More Reliable Strategies
* SYN-cache
* SYN-cookies
* Firewall & Proxy
