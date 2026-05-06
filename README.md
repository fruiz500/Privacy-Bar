# Privacy Bar: Post-Quantum Secure Browser Communication
### A Hybrid PQC Implementation for the Modern Web

**Privacy Bar** is a Chrome extension (Manifest V3) designed to protect digital communications against the "Harvest Now, Decrypt Later" threat. It represents the evolution of the PassLok, KyberLock, and SynthPass ecosystem, condensed into a streamlined, high-performance extension for Chromium browsers.

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

## Acknowledgements
  PassLok contains and/or links to code from a number of open source
  projects on GitHub, including the Tweet NaCl crypto library, and others.

---

## Cryptography Notice
  This distribution includes cryptographic software. The country in
  which you currently reside may have restrictions on the import,
  possession, use, and/or re-export to another country, of encryption
  software. BEFORE using any encryption software, please check your
  country's laws, regulations and policies concerning the import,
  possession, or use, and re-export of encryption software, to see if
  this is permitted. See <http://www.wassenaar.org/> for more
  information.

  The U.S. Government Department of Commerce, Bureau of Industry and
  Security (BIS), has classified this software as Export Commodity
  Control Number (ECCN) 5D002.C.1, which includes information security
  software using or performing cryptographic functions with asymmetric
  algorithms. The form and manner of this distribution makes it
  eligible for export under the License Exception ENC Technology
  Software Unrestricted (TSU) exception (see the BIS Export
  Administration Regulations, Section 740.13) for both object code and
  source code.

  ---
  
*Developed by a Professor & Cryptography Researcher.*
