# DNSTT Runner

A full-featured automation script to run **DNSTT + SSH + HAProxy** as a managed service with multiple parallel tunnels and load balancing.

---

## 1. Server Setup (Required)

Before using this script, you **must install and configure your DNSTT server** using this official guide:

👉 **Server install tutorial:**  
https://github.com/bugfloyd/dnstt-deploy

This prepares:
- DNSTT server
- Public key
- Domain
- DNS records
- SSH Mode!!!

Without this step, the client will not work.

---

## 2. How It Works
[ Your Device ] -> [ Bridge VPS ] -> [ DNSTT Instances with Load Balancer ]

### Installation

``` curl -fsSL https://raw.githubusercontent.com/hossinasaadi/dnstt-runner/main/install.sh | sudo bash ```

### Flow explanation

1. Your client connects to a **Bridge VPS**
2. DNSTT creates **multiple tunnels** over DNS  
3. Each tunnel runs its own **SSH SOCKS proxy**
4. HAProxy load balances between them
5. You connect to **one stable SOCKS5 endpoint**

---

## 3. Default HAProxy Settings

For safety, HAProxy listens only on **localhost** by default:

`127.0.0.1:10802`

### Change listening address

Edit: /etc/dnstt-runner/dnstt-runner.env

Example:
```
HAPROXY_LISTEN_IP=“0.0.0.0”
HAPROXY_LISTEN_PORT=“10802”
```

Then restart: systemctl restart dnstt-runner

---

## 4. Security Tip (Important)

For better safety:

> Use **3x-ui inbound with dialer proxy**  
> Forward traffic through **local SOCKS5**

---

## 5. Commands

```
sudo ./install.sh install
sudo ./install.sh start
sudo ./install.sh stop
sudo ./install.sh restart
sudo ./install.sh status
sudo ./install.sh logs
```

## 6. Credits & Thanks ❤️

DNSTT Project  
https://www.bamsoftware.com/software/dnstt/

Bugfloyd  
https://github.com/bugfloyd

---

## 7. Final Notes

- Designed for **SSH mode only**
- Supports:
  - Multi-instance tunneling
  - Auto restart
  - HAProxy load balancing
- Tested on Ubuntu

---

Happy tunneling 🚀