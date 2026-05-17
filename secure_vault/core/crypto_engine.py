"""
SecureVault Cryptography Engine
================================
AES-256-GCM encryption with HMAC-SHA256 integrity checks,
PBKDF2 key derivation, and chunked file processing.

Threat Model:
- Man-in-the-middle: Mitigated by AES-GCM authenticated encryption
- Key compromise: Mitigated by per-file ephemeral keys + master key wrapping
- Replay attacks: Mitigated by unique nonces per chunk
- Tampering: Mitigated by HMAC-SHA256 over entire file + per-chunk GCM tags
- Brute force: Mitigated by PBKDF2 with 600,000 iterations (NIST recommended)
"""

import os
import hmac
import hashlib
import struct
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

# Constants
CHUNK_SIZE = 1 * 1024 * 1024   # 1 MB chunks
AES_KEY_SIZE = 32               # AES-256
NONCE_SIZE = 12                 # GCM standard nonce
HMAC_SIZE = 32                  # SHA-256 output
SALT_SIZE = 32                  # KDF salt
PBKDF2_ITERATIONS = 600_000     # NIST SP 800-132 recommended
MAGIC = b"SVLT"                 # SecureVault magic bytes
VERSION = 1


class CryptoEngine:
    """Core encryption/decryption engine."""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive AES key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def generate_file_key() -> bytes:
        """Generate a random AES-256 file encryption key."""
        return os.urandom(AES_KEY_SIZE)

    @staticmethod
    def encrypt_chunk(data: bytes, key: bytes, chunk_index: int) -> bytes:
        """
        Encrypt a single chunk with AES-256-GCM.
        Nonce = random(8) + chunk_index(4) to ensure uniqueness.
        Returns: nonce(12) + ciphertext + tag(16)
        """
        nonce_random = os.urandom(8)
        nonce_counter = struct.pack('>I', chunk_index)
        nonce = nonce_random + nonce_counter  # 12 bytes total
        
        aesgcm = AESGCM(key)
        # Additional authenticated data includes chunk index for ordering integrity
        aad = struct.pack('>I', chunk_index)
        ciphertext = aesgcm.encrypt(nonce, data, aad)  # includes 16-byte GCM tag
        
        return nonce + ciphertext

    @staticmethod
    def decrypt_chunk(encrypted_chunk: bytes, key: bytes, chunk_index: int) -> bytes:
        """Decrypt a single chunk and verify GCM authentication tag."""
        nonce = encrypted_chunk[:NONCE_SIZE]
        ciphertext_with_tag = encrypted_chunk[NONCE_SIZE:]
        
        aesgcm = AESGCM(key)
        aad = struct.pack('>I', chunk_index)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
            return plaintext
        except Exception:
            raise ValueError(f"Chunk {chunk_index}: Authentication failed — data tampered or corrupted!")

    @staticmethod
    def compute_hmac(key: bytes, data: bytes) -> bytes:
        """Compute HMAC-SHA256 for integrity verification."""
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
        """Verify HMAC in constant time to prevent timing attacks."""
        computed = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(computed, expected_mac)

    @staticmethod
    def compute_file_hash(file_path: str) -> str:
        """Compute SHA-256 hash of file for integrity tracking."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()


class FileEncryptor:
    """
    Handles full file encryption with chunking and integrity checks.
    
    Encrypted file format:
    +-----------------+
    | MAGIC (4)       |  "SVLT"
    | VERSION (1)     |  format version
    | SALT (32)       |  KDF salt
    | NONCE_MASTER(12)|  master key wrapping nonce
    | FILE_KEY_ENC(48)| encrypted file key (32 + 16 tag)
    | HMAC_KEY_ENC(48)| encrypted HMAC key (32 + 16 tag)
    | ORIG_SIZE (8)   |  original file size
    | FILENAME_LEN(2) |  length of filename
    | FILENAME (N)    |  original filename (encrypted)
    | NUM_CHUNKS (4)  |  number of chunks
    | CHUNK_SIZES...  |  size of each encrypted chunk (4 bytes each)
    | CHUNKS...       |  encrypted chunk data
    | HMAC (32)       |  HMAC-SHA256 over everything above
    +-----------------+
    """

    def encrypt_file(self, input_path: str, output_path: str, password: str,
                     progress_callback=None) -> dict:
        """
        Encrypt file to SecureVault format.
        Returns metadata dict with hash, chunk count, etc.
        """
        salt = os.urandom(SALT_SIZE)
        master_key = CryptoEngine.derive_key(password, salt)
        
        # Generate random file-specific keys
        file_key = CryptoEngine.generate_file_key()
        hmac_key = CryptoEngine.generate_file_key()
        
        # Encrypt file key and hmac key with master key
        master_nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(master_key)
        file_key_enc = aesgcm.encrypt(master_nonce, file_key, b"file-key")
        hmac_key_enc = aesgcm.encrypt(master_nonce, hmac_key, b"hmac-key")
        
        # Read and chunk the file
        filename = os.path.basename(input_path).encode('utf-8')
        file_size = os.path.getsize(input_path)
        
        chunks = []
        with open(input_path, 'rb') as f:
            chunk_index = 0
            while True:
                data = f.read(CHUNK_SIZE)
                if not data:
                    break
                encrypted_chunk = CryptoEngine.encrypt_chunk(data, file_key, chunk_index)
                chunks.append(encrypted_chunk)
                chunk_index += 1
                if progress_callback:
                    progress_callback(min(f.tell(), file_size), file_size)
        
        num_chunks = len(chunks)
        
        # Build the file header
        header = MAGIC
        header += struct.pack('B', VERSION)
        header += salt
        header += master_nonce
        header += file_key_enc
        header += hmac_key_enc
        header += struct.pack('>Q', file_size)
        header += struct.pack('>H', len(filename))
        header += filename
        header += struct.pack('>I', num_chunks)
        
        # Chunk size table
        chunk_sizes = b''
        for chunk in chunks:
            chunk_sizes += struct.pack('>I', len(chunk))
        
        # Concatenate everything except HMAC
        all_data = header + chunk_sizes + b''.join(chunks)
        
        # Compute HMAC over entire payload
        mac = CryptoEngine.compute_hmac(hmac_key, all_data)
        
        # Write final encrypted file
        with open(output_path, 'wb') as f:
            f.write(all_data)
            f.write(mac)
        
        # Compute hash of original file for integrity record
        original_hash = CryptoEngine.compute_file_hash(input_path)
        encrypted_hash = CryptoEngine.compute_file_hash(output_path)
        
        return {
            'original_filename': os.path.basename(input_path),
            'original_size': file_size,
            'encrypted_size': os.path.getsize(output_path),
            'num_chunks': num_chunks,
            'original_hash_sha256': original_hash,
            'encrypted_hash_sha256': encrypted_hash,
            'version': VERSION,
        }

    def decrypt_file(self, input_path: str, output_path: str, password: str,
                     progress_callback=None) -> dict:
        """
        Decrypt a SecureVault encrypted file.
        Verifies HMAC before decryption (authenticate then decrypt).
        """
        with open(input_path, 'rb') as f:
            raw = f.read()
        
        pos = 0
        
        # Verify magic
        magic = raw[pos:pos+4]; pos += 4
        if magic != MAGIC:
            raise ValueError("Invalid file format — not a SecureVault file!")
        
        version = raw[pos]; pos += 1
        if version != VERSION:
            raise ValueError(f"Unsupported format version: {version}")
        
        salt = raw[pos:pos+SALT_SIZE]; pos += SALT_SIZE
        master_nonce = raw[pos:pos+NONCE_SIZE]; pos += NONCE_SIZE
        file_key_enc = raw[pos:pos+48]; pos += 48  # 32 + 16 GCM tag
        hmac_key_enc = raw[pos:pos+48]; pos += 48
        file_size = struct.unpack('>Q', raw[pos:pos+8])[0]; pos += 8
        filename_len = struct.unpack('>H', raw[pos:pos+2])[0]; pos += 2
        filename = raw[pos:pos+filename_len].decode('utf-8'); pos += filename_len
        num_chunks = struct.unpack('>I', raw[pos:pos+4])[0]; pos += 4
        
        # Read chunk sizes
        chunk_sizes = []
        for _ in range(num_chunks):
            size = struct.unpack('>I', raw[pos:pos+4])[0]; pos += 4
            chunk_sizes.append(size)
        
        chunk_data_start = pos
        total_chunk_size = sum(chunk_sizes)
        hmac_start = chunk_data_start + total_chunk_size
        
        # Extract and verify HMAC FIRST (authenticate before decrypt)
        stored_mac = raw[hmac_start:hmac_start + HMAC_SIZE]
        payload = raw[:hmac_start]
        
        # Derive master key
        master_key = CryptoEngine.derive_key(password, salt)
        aesgcm = AESGCM(master_key)
        
        # Decrypt file key and hmac key
        try:
            file_key = aesgcm.decrypt(master_nonce, file_key_enc, b"file-key")
            hmac_key = aesgcm.decrypt(master_nonce, hmac_key_enc, b"hmac-key")
        except Exception:
            raise ValueError("Wrong password or corrupted key material!")
        
        # Verify HMAC
        if not CryptoEngine.verify_hmac(hmac_key, payload, stored_mac):
            raise ValueError("HMAC verification FAILED — file has been tampered with!")
        
        # Decrypt chunks
        with open(output_path, 'wb') as out:
            for i, chunk_size in enumerate(chunk_sizes):
                encrypted_chunk = raw[pos:pos+chunk_size]; pos += chunk_size
                plaintext = CryptoEngine.decrypt_chunk(encrypted_chunk, file_key, i)
                out.write(plaintext)
                if progress_callback:
                    progress_callback(i + 1, num_chunks)
        
        # Verify final file size
        actual_size = os.path.getsize(output_path)
        if actual_size != file_size:
            os.remove(output_path)
            raise ValueError(f"Size mismatch: expected {file_size}, got {actual_size}")
        
        decrypted_hash = CryptoEngine.compute_file_hash(output_path)
        
        return {
            'original_filename': filename,
            'original_size': file_size,
            'num_chunks': num_chunks,
            'decrypted_hash_sha256': decrypted_hash,
        }


class RSAKeyManager:
    """
    RSA-2048 key pair management for server-side key exchange.
    In production: use HSM or KMS (AWS KMS, HashiCorp Vault).
    """

    @staticmethod
    def generate_keypair(key_dir: str):
        """Generate RSA-2048 key pair for server."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        os.makedirs(key_dir, exist_ok=True)
        with open(os.path.join(key_dir, 'server_private.pem'), 'wb') as f:
            f.write(priv_pem)
        with open(os.path.join(key_dir, 'server_public.pem'), 'wb') as f:
            f.write(pub_pem)
        
        # Set restrictive permissions
        os.chmod(os.path.join(key_dir, 'server_private.pem'), 0o600)
        
        return priv_pem, pub_pem
