# Operation: Dark Gravity - CTF Lab

## 🎯 Description

This is a vulnerable lab for the PT1 Capstone Challenge. Students must:

1. Discover the hidden `/portal` directory
2. Exploit the file upload vulnerability
3. Get a reverse shell as `www-data`
4. Find user flag in `/home/developer/user.txt`
5. Escalate privileges using `sudo vim`
6. Get root flag in `/root/root.txt`

## 🚀 Quick Start

```bash
# Build and run
docker-compose up -d --build

# Access the lab
# Web: http://localhost:8888
# SSH: ssh localhost -p 2222
```

## 🔐 Flags

| Flag | Location | Value |
|------|----------|-------|
| User | `/home/developer/user.txt` | `AG{W3b_Sh3ll_M4st3r_2025}` |
| Root | `/root/root.txt` | `AG{R00t_Pr1vEsc_K1ng_2025}` |

## ⚠️ Vulnerabilities

1. **File Upload Bypass** - Only checks extension, can be bypassed with `.php.jpg`
2. **SUDO Misconfiguration** - `www-data` can run `vim` as root
3. **Information Disclosure** - Hidden `/portal` directory

## 🛠️ Ports

- `8888` → Apache (80)
- `2222` → SSH (22)
