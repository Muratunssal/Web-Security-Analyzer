from scapy.all import *

def dhcp_spoof(packet):
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        fake_dns = "192.168.1.100"
        print("[*] DHCP Discover yakalandı, sahte yanıt hazırlanıyor...")
        # Burada tam bir DHCP Offer paketi oluşturulabilir.

sniff(filter="udp and (port 67 or 68)", prn=dhcp_spoof)
