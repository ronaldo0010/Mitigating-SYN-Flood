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

## TCP SYN-Attack
* Malicious client sends 1 part of 3-way handshake, SYN packet.
* The server notices this flow, allocates resources for the connection
* The server acknowledges by sending a TCP SYN ACK packet and continues waiting for the client's response.
* The client continues sending these TCP/IP requests to establish various TCP connections.
* Indefinitely, the server can run out of resources allocated for these connections - resulting in segfaults or deadlocks.

## Traditional SYN-Attack Mitigation Stragtegies
### Naive Strategies
* Increased Server backlog
  - Scaling the capasity of TCP stack storage.
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
  - Ensures that only legitmate connections are established with the end user/server
  -  By handling the 3-way handshake on the firewall side and passing the connection via proxy to server [rfc4987, 2007].
  

## But Why? Why use a P4 programmable dataplane? 


## P4 SYN-Attack Mitigation Stragtegies


