# 🔐 SecureVault — Encrypted File Transfer & Storage

A production-grade encrypted file storage system with AES-256-GCM encryption,
HMAC-SHA256 integrity checks, chunked file processing, and a stunning cyber-aesthetic GUI.

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Launch everything (vault server + GUI)
python run.py

# Open your browser
open http://localhost:5000
```

---

## 🏗️ Architecture

```
secure_vault/
├── core/
│   └── crypto_engine.py    # AES-256-GCM, HMAC-SHA256, PBKDF2, RSA
├── server/
│   └── server.py           # Flask vault server (port 5001)
├── client/
│   └── vault_client.py     # Python client library
├── templates/
│   └── index.html          # Stunning cyber-aesthetic GUI
├── server_storage/         # Encrypted blobs stored here
├── keys/                   # RSA key pair (server-side)
├── downloads/              # Decrypted files (temp)
├── app.py                  # GUI Flask app (port 5000)
├── run.py                  # Launcher
└── requirements.txt
```

---

## 🔒 Cryptographic Design

### Encrypted File Format (.svlt)

```
┌─────────────────────────────────────────────────────────┐
│ MAGIC(4) │ VER(1) │ SALT(32) │ MASTER_NONCE(12)         │
│ FILE_KEY_ENC(48) │ HMAC_KEY_ENC(48)                     │
│ ORIG_SIZE(8) │ FILENAME_LEN(2) │ FILENAME(N)            │
│ NUM_CHUNKS(4) │ CHUNK_SIZES(4×N)                        │
│ [CHUNK_0: NONCE(12) + CIPHERTEXT + GCM_TAG(16)]        │
│ [CHUNK_1: ...]  ···  [CHUNK_N: ...]                     │
│ HMAC-SHA256(32) ← covers ALL bytes above               │
└─────────────────────────────────────────────────────────┘
```

### Key Hierarchy (Envelope Encryption)

```
Password
    │
    ▼ PBKDF2-HMAC-SHA256 (600,000 iter, 32-byte salt)
Master Key (AES-256)
    │
    ├──► Wrap File Key  (random AES-256)  → stored encrypted in header
    └──► Wrap HMAC Key  (random AES-256)  → stored encrypted in header
              │                    │
              ▼                    ▼
        Encrypt chunks      MAC entire payload
        (AES-256-GCM)       (HMAC-SHA256)
```

### Per-Chunk Nonce Construction

```
nonce (12 bytes) = random(8) || chunk_index_be(4)
aad              = chunk_index_be(4)   ← prevents chunk reordering
```

---

## 🛡️ Threat Model

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Man-in-the-Middle | HIGH | E2E encryption — ciphertext only in transit |
| Compromised Server | HIGH | Zero-knowledge — password never sent to server |
| Storage Tampering | HIGH | HMAC-SHA256 + blob hash verified before decrypt |
| Replay Attack | MEDIUM | Per-chunk nonce + chunk index AAD |
| Weak Password | MEDIUM | PBKDF2 600k iterations + 32-byte random salt |
| Timing Attack (HMAC) | MEDIUM | `hmac.compare_digest()` constant-time |
| Nonce Reuse | MEDIUM | Per-file random key + random nonce prefix |
| Plaintext Temp Files | LOW | os.urandom() overwrite before unlink |
| Data After Deletion | LOW | 3-pass overwrite (DoD 5220.22-M simplified) |
| Padding Oracle | LOW | GCM mode (no padding) + authenticate-then-decrypt |

---

## 🔑 Key Management Notes

**Current (Development)**
- Password-derived master key via PBKDF2
- Server RSA-2048 key pair stored on disk (restricted permissions)

**Production Recommendations**
- Use AWS KMS / HashiCorp Vault / Azure Key Vault
- Hardware Security Module (HSM) for server keys
- Mutual TLS (mTLS) between client and server
- Argon2id instead of PBKDF2 for even stronger KDF
- Per-user file ACLs with JWT authentication
- Key rotation strategy for stored files

---

## 🌐 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server status + stats |
| GET | `/api/pubkey` | Server RSA public key |
| POST | `/api/upload` | Upload encrypted file |
| GET | `/api/files` | List all vault files |
| GET | `/api/download/<id>` | Download encrypted blob |
| GET | `/api/file/<id>` | Get file metadata |
| DELETE | `/api/delete/<id>` | Secure delete (3-pass) |
| GET | `/api/verify/<id>` | Verify blob integrity |

---

## 📐 Security Properties

- **Confidentiality**: AES-256-GCM with unique per-file key
- **Integrity**: HMAC-SHA256 (full payload) + GCM auth tag (per chunk)
- **Authenticity**: Password-derived key proves knowledge
- **Forward Secrecy**: Per-file random keys — past files safe even if master key compromised
- **Tamper Evidence**: Any bit flip → authentication failure
- **Non-repudiation**: Upload timestamp + client IP logged
- **Secure Deletion**: 3-pass overwrite + temp file wiping

---

## ⚡ Performance

- 1MB chunk size balances memory usage vs. overhead
- Streaming upload (no full file in RAM)
- Parallel-safe with thread locks on metadata
- SHA-256 blob hash computed on upload and verified on download

---

*Built with: Python · Flask · cryptography (OpenSSL bindings) · AES-256-GCM · HMAC-SHA256 · PBKDF2*
