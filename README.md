<div align="center">

# 🛡️ NovaLink VPN v2.0
</div>

## 🚀 What's New in v2.0
I've completely overhauled the security layer to bypass modern firewalls and improve performance on CPUs without AES acceleration.



### 🛡️ Advanced Security
* **ChaCha20-Poly1305 (AEAD):** Switched to ChaCha20 for top-tier encryption and authentication. It's faster than AES in software and extremely secure.
* **TLS Mimicry:** My favorite part. NovaLink now wraps UDP packets to look exactly like **TLS Application Data**. This helps sneak past DPI systems that try to block VPN protocols.
* **Perfect Forward Secrecy (PFS):** Session keys are generated via **ECDH (X25519)**. Even if one key is compromised, your past traffic stays safe.
* **Anti-Traffic Analysis:** All packets are padded to fixed sizes. This prevents ISP snoops from guessing what you're doing based on packet length.

## 🛠 Updated Tech Stack
| Feature | Implementation |
| :--- | :--- |
| **Cipher** | ChaCha20-Poly1305 (AEAD) |
| **Handshake** | ECDH X25519 |
| **Obfuscation** | TLS 1.3 Header Mimicry |
| **Packet Padding** | Constant bit-rate simulation |

---

## 📊 Performance Status
- **Stealth:** Effectively bypasses basic DPI "fingerprinting".
- **Efficiency:** Minimal overhead thanks to ChaCha20's low CPU cycle count.
- **Reliability:** Validated against packet loss and reordering.