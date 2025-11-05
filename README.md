# 🔨 Go SYN Flood Tool (Raw Sockets)

This tool crafts and sends raw TCP SYN packets to a single IP address or an entire CIDR block, allowing controlled flooding for penetration testing, lab simulations, and CTF scenarios. Built in pure Go with zero external dependencies — perfect for use in environments like TryHackMe or Hack The Box where Go is required.

> ⚠️ **Use responsibly.** This tool is designed for legal, ethical, and lab-based testing only.

---

## ⚙️ Features

- ✅ Raw socket packet crafting (IP + TCP headers)
- ✅ Supports single IP or full `/24` CIDR ranges
- ✅ Source port randomization
- ✅ Color-coded terminal output
- ✅ No external libraries required

---

## 🚀 Usage

Run with root privileges:

```bash
sudo go run synflood_userinput.go
```

You'll be prompted for:

1. **Target IP or CIDR block**
2. **Destination port**

---

## 📥 Example

```
Enter IP address or CIDR (e.g. 10.10.10.5 or 10.10.10.0/24): 10.10.10.5
Enter target port (e.g. 80): 80
[*] Starting SYN flood...
[+] Sent packet to 10.10.10.5
[+] Sent packet to 10.10.10.5
[+] Sent packet to 10.10.10.5
...
```

---

## 🧠 Tip

This is ideal for CTF-style infrastructure where taking down a server (e.g., active/passive failover) reveals flags or escalates privileges on another box.

---
