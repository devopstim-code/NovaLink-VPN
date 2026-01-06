<div align="center">

# 🛡️ NovaLink VPN
**A lightweight, blazing fast L3 tunneling solution written in C++20.**

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue?style=for-the-badge&logo=c%2B%2B)](https://isocpp.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://kernel.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)

<p align="center">
  <a href="#-the-idea">The Idea</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-performance">Performance</a> •
  <a href="#-getting-started">Getting Started</a>
</p>

---
</div>

## 📖 The Idea
I built **NovaLink** because I wanted a VPN that doesn't feel like a bloated monster. It's a clean, Layer 3 implementation that creates an encrypted tunnel between a client and a server. No fancy UI, no useless features — just pure performance and solid crypto.



## 🛠 Tech Stack
I went with **C++20** and modern Linux primitives to keep it close to the metal:

* **Networking:** Non-blocking I/O powered by `epoll`. It’s built to handle many connections without sweating.
* **Cryptography:** Using `Curve25519` for the handshake and `AES-256-GCM` for the data flow. Fast and secure.
* **Engine:** Direct integration with Linux `TUN/TAP` devices to route traffic at the IP level.

## 📊 Performance & Stress Tests
I've put this thing through the ringer to make sure it doesn't crash when things get heavy:

| Metric | Result |
| :--- | :--- |
| **Concurrency** | **400+** stable connections (tested via `wrk`) |
| **Latency** | **~0.1ms** RTT (it's fast, really fast) |
| **Memory** | **Zero leaks.** Verified with `Valgrind` |

## 🚀 Getting Started

### Build
You'll need `cmake` and a compiler that supports C++20 (like GCC 10+ or Clang).

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Run it

Since we're touching network interfaces (TUN), you'll need sudo.

1. Fire up the Server:
```Bash

sudo ./bin/novalink_server 55555
```
2. Connect the Client:
```Bash

# Format: ./client <server_ip> <port> <virtual_ip>
sudo ./bin/novalink_client 127.0.0.1 55555 10.8.0.3
```
<div align="center"> <sub>Made by a dev who cares about performance.</sub> </div>
