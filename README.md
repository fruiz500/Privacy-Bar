# Privacy Bar: Post-Quantum Secure Browser Communication
### A Hybrid PQC Implementation for the Modern Web

**Privacy Bar** is a Chrome extension (Manifest V3) designed to protect digital communications against the "Harvest Now, Decrypt Later" threat. It represents the evolution of the PassLok, KyberLock, and SynthPass ecosystem, condensed into a streamlined, high-performance browser tool.

---

## 🛡️ The Security Manifesto
In an era of emerging quantum capabilities, classical encryption (RSA, ECC) is no longer a permanent vault. Privacy Bar employs a **Hybrid Cryptographic Model** to ensure long-term data integrity.

### Six Pillars of Security:
1.  **Post-Quantum Hybrid Encryption:** Implements **ML-KEM (Kyber)** primitives alongside classical algorithms.
2.  **The "Pad Mode":** Uses any previously shared file as a high-entropy source for information-theoretic security.
3.  **Password Synthesis:** A vaultless approach to credential management—generating breach-proof passwords on-the-fly with no central database.
4.  **Undetectable Steganography:** Advanced image-based steganography designed to withstand automated pattern analysis and country-wide surveillance.
5.  **Page Isolation:** A "Zero-Trust" execution environment that protects the extension logic from malicious tabs or compromised extensions.
6.  **Memory Hygiene:** Master keys exist only in volatile memory and are automatically wiped after five minutes of inactivity.

---

## 🔍 Audit Guide for Security Researchers
This repository is published to allow for public verification of the underlying mathematics and implementation. As a researcher-led project, transparency is our primary trust mechanism.

### Critical Files:
* `/src/sidepanel_encrypt.js`: Primary encryption logic and hybrid assembly, including NIST-standardized ML-KEM algorithms.
* `/src/sidepanel_decrypt.js`: Primary decryption logic and hybrid assembly, including NIST-standardized ML-KEM algorithms.
* `/src/crypto-extra.js`: Implementation of file entropy extraction for pad mode.
* `/src/sidepanel_stego.js`: The engine for bit-level manipulation in image carriers.
* `/src/sidepanel_passwords.js`: Password synthesis based on host name and Master Key.
* `/src/pro-license.js`: **Note:** This repository contains a *mock* implementation of the license check logic. Production builds use a cryptographically signed signature verification system integrated with Lemon Squeezy.

---

## ⚖️ License
This project is licensed under the **PolyForm Shield License 1.0.0**.

* **Audit & Personal Use:** You are encouraged to read, audit, and use the code for personal evaluation.
* **Commercial Restriction:** You may **not** use this software or its derivatives to provide a competing service.

See [LICENSE.md](LICENSE.md) for the full legal text.

---

## 🚀 Installation & Official Builds
The official, signed, and supported version of Privacy Bar is available on the Chrome Web Store. The Web Store version includes automatic updates and full feature access.

**[Download Privacy Bar on the Chrome Web Store](https://chrome.google.com/webstore/detail/objpfdibjogbdpjjpomnoaflkgdeaanb)**

---

## 🌐 Related Projects
Privacy Bar is part of a broader privacy ecosystem designed for cross-compatibility. Open sources also available on GitHub:
* **[PassLok:](https://github.com/fruiz500/PassLok-Privacy)** The foundation for secure, easy-to-use encryption.
* **[KyberLock:](https://github.com/fruiz500/KyberLock)** Dedicated post-quantum implementation.
* **[SynthPass:](https://github.com/fruiz500/SynthPass)** The original password synthesis logic.

---
*Developed by a Professor & Cryptography Researcher.*
