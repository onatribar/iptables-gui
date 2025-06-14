# Iptables‑GUI

GUI wrapper for interacting with Linux **iptables** rules, for the CSE439 Computer Security course in Spring 2025.

---

## Platform

* Runs only on Linux (requires `iptables-nft`).
* Developed and tested on **Fedora Linux 42** (kernel 6.14, iptables 1.8.11‑nf\_tables).
  Any modern distro with PolicyKit (`pkexec`) should work the same.

---

## Software requirements

* **Python >= 3.11**
* **PyQt5 >= 5.15**
* **iptables‑nft >= 1.8**
* **PolicyKit** (`pkexec`)
* **hping3 3.x** *(optional to test traffic)*
* **netcat (openbsd‑nc)** *(fallback to test traffic)*

---

## Running the GUI

```bash
cd ~/iptables-gui
# run as root so iptables writes succeed
pkexec python3 main.py
# or
sudo python3 main.py
```

### Basic workflow

1. **Add single rule**: fill protocol / IP / ports / action, click **Add Rule(s)**.
2. **Bulk whitelist or blacklist**: paste one IP/CIDR per line, click **Add Rule(s)**.
3. **Buttons**

   * **Refresh**: update live counters;
   * **Toggle Disable**: soft on/off selected rule;
   * **Delete Selected**: remove rule permanently;
   * **Reorder by Usage**: sort rules by packet hit‑count.

---
## Testing Guide

## UDP traffic generation

Before sending test packets, add arbitrary fake loopback IPs:

```bash
sudo ip addr add 10.0.0.61/32 dev lo # accept
sudo ip addr add 10.0.0.62/32 dev lo # drop
```

Add rules accordingly for each loopback IP.

Start a UDP listener on an arbitrary port:

```bash
sudo nc -ul 9999
```

Then send traffic to your machine via fake loopback IPs:

```bash
# one UDP datagram from whitelisted IP
printf 'hi' | sudo nc -u -s 10.0.0.61 127.0.0.1 9999

# one UDP datagram from blacklisted IP
printf 'ho' | sudo nc -u -s 10.0.0.62 127.0.0.1 9999
```

Click **Refresh** in the GUI for *Packets* column to increment.

---

## Automated tests the backend logic only

```bash
cd ~/iptables-gui
sudo python3 test.py
```

The script:

1. Saves current IPv4 rules (`iptables-save`).
2. Adds **ACCEPT udp 127.0.0.1:9999**.
3. Confirms counter rises after traffic.
4. Disables the rule, confirms counter doesn't change.
5. Re‑enables, deletes the rule, reorders.
6. Restores the original firewall (`iptables-restore`).

Successful run prints **`ALL TESTS PASSED! YIPPIE!`**.

---

## Demo for Whitelist / Blacklist

```bash
# create two temporary loopback aliases
sudo ip addr add 10.0.0.71/32 dev lo   # whitelist
sudo ip addr add 10.0.0.72/32 dev lo   # blacklist
```

1. In the GUI paste `10.0.0.71` into **Whitelist**, `10.0.0.72` into **Blacklist**, click **Add Rule(s)**.

2. In a terminal, run a test listener to catch packets:

```bash
sudo nc -u -l 9999
```

3. Send traffic:

```bash
printf hi | sudo nc -u -s 10.0.0.72 127.0.0.1 9999   # allowed
printf ho | sudo nc -u -s 10.0.0.72 127.0.0.1 9999   # blocked
```

4. Click **Refresh**: packets counted under their respective rules.

Cleanup:

```bash
sudo ip addr del 10.0.0.71/32 dev lo
sudo ip addr del 10.0.0.72/32 dev lo
sudo iptables -F INPUT
```

---

**Note:** IP addresses like `127.0.0.1`, `0.0.0.0`, or local loopback aliases (`10.0.0.X/32`) are safe for local testing. External test scenarios may need adjustments.
