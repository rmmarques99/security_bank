# 💳 ATM Communication – Secure Client/Server Banking System

This project simulates a secure client-server banking system implemented in Python. It was developed as part of the **Applied Security** course at the MSc in Computer Engineering / Information Security, Faculty of Sciences, University of Lisbon.

---

## Objectives

This system was designed with a strong emphasis on security, ensuring:

-  **Confidentiality** – using AES-CBC encryption
-  **Integrity** – using HMAC-SHA256
-  **Authenticity** – RSA-based key exchange + local `.card` authentication
-  **Availability** – protections against replay and denial-of-service (DoS) attacks

---

## Key Technologies & Concepts

- **Python 3**
- **Sockets (TCP/IP)**
- **RSA 2048-bit + OAEP** for secure key exchange
- **AES-CBC (AES-128)** for symmetric encryption
- **HMAC-SHA256** for message authentication
- **Argon2id** for key derivation and PIN hashing
- **Threading, Semaphores & Locks** for safe concurrency

---

##  Architecture

###  `Bank.py` – Server

- Handles account management and transaction processing
- Uses RSA to decrypt the session key from the client
- Derives AES/HMAC keys from session key + salt using Argon2id
- Applies strict input validation, per-account locks, and rollback support
- Limits active connections (max 20) using `threading.Semaphore`
- Handles SIGTERM/SIGINT gracefully

### `ATM.py` – Client

- Generates a unique 32-byte session key and encrypts it with the bank's public RSA key
- Creates and uses a local `.card` file for authentication
- Derives AES and HMAC keys from session key using Argon2id
- Sends encrypted transaction requests (create, deposit, withdraw, get balance)

---

## 🛡️ Security Highlights

| Security Property / Attack Type | Mitigation                                                                 |
|----------------------------------|----------------------------------------------------------------------------|
|  Confidentiality               | AES encryption (CBC mode) with fresh IV for each message                  |
|  Integrity                     | HMAC-SHA256 authentication covering salt, IV and ciphertext              |
|  Authenticity                 | RSA-OAEP key exchange + `.card`-based client authentication              |
|  Replay Attacks                | Unique `nonce` + timestamp in every request (10s validity window)        |
|  DoS Attacks                   | 2048-byte max packet size, socket timeouts, semaphore (20 threads max)   |
|  Race Conditions               | Fine-grained per-account locks and global locking on shared structures   |
|  Key Separation                | AES and HMAC keys derived separately using Argon2id + unique salt        |


---

## ▶ Running the System

###  Install Dependencies

```bash
pip install cryptography argon2-cffi pycryptodome



##  Start the Server (Bank)
python Bank.py -p 3000 -s bank.auth


## 🏦 Use the Client (ATM)
# Create a new account with initial balance
python ATM.py -a john -n 100.00

# Deposit funds
python ATM.py -a john -d 50.00

# Withdraw funds
python ATM.py -a john -w 25.00

# Check balance
python ATM.py -a john -g



##  Project Structure
├── ATM.py            # Secure ATM client
├── Bank.py           # Secure banking server
├── bank.auth         # Bank's RSA public key (shared with clients)
├── bank.auth.key     # Bank's RSA private key (kept secret on server)
├── <user>.card       # Client authentication file (local only)
└── README.md         # This file



Project developed during the "Build It" phase of the ATM Communication Challenge
(University of Lisbon – 2024/2025)
