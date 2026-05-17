"""
SecureVault Resume Engine
==========================
Resumable chunked upload/download with checkpoint persistence.

How resume works:
- Before encrypting, a .checkpoint file is written listing each chunk's status
- If the process is interrupted, on restart we find the checkpoint and skip done chunks  
- The server stores chunks individually under a session ID
- Once all chunks are uploaded, the server assembles the final .svlt blob
- Checkpoint files are wiped on successful completion

Server-side resume endpoints:
  POST /api/session/start          → session_id
  POST /api/session/<id>/chunk/<n> → upload one chunk
  GET  /api/session/<id>/status    → which chunks arrived
  POST /api/session/<id>/finalize  → assemble final blob
  DELETE /api/session/<id>         → abort session
"""

import os
import sys
import json
import time
import struct
import hashlib
import requests
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.crypto_engine import (
    FileEncryptor, CryptoEngine, CryptoEngine as CE,
    AES_KEY_SIZE, NONCE_SIZE, HMAC_SIZE, SALT_SIZE,
    PBKDF2_ITERATIONS, CHUNK_SIZE, MAGIC, VERSION
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac as hmaclib
import os


CHECKPOINT_EXT = '.svlt_checkpoint'


class CheckpointManager:
    """Persists upload/download progress so it can be resumed."""

    def __init__(self, checkpoint_path: str):
        self.path = checkpoint_path

    def save(self, data: dict):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self) -> Optional[dict]:
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path) as f:
                return json.load(f)
        except Exception:
            return None

    def mark_chunk_done(self, chunk_idx: int):
        data = self.load() or {}
        done = set(data.get('done_chunks', []))
        done.add(chunk_idx)
        data['done_chunks'] = sorted(done)
        self.save(data)

    def is_chunk_done(self, chunk_idx: int) -> bool:
        data = self.load() or {}
        return chunk_idx in data.get('done_chunks', [])

    def complete(self):
        """Remove checkpoint on success."""
        if os.path.exists(self.path):
            os.unlink(self.path)


class ResumableUploader:
    """
    Encrypts and uploads a file in chunks with resume support.

    Usage:
        uploader = ResumableUploader(server_url)
        result = uploader.upload('bigfile.zip', 'password', progress_cb)
        # If interrupted, call again with same file+password — it resumes!
    """

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()

    def upload(self, file_path: str, password: str,
               progress_callback: Optional[Callable] = None) -> dict:
        """
        Upload with resume support.
        Checkpoint stored at <file_path>.svlt_checkpoint
        """
        file_path = Path(file_path)
        checkpoint_path = str(file_path) + CHECKPOINT_EXT
        cp = CheckpointManager(checkpoint_path)

        existing = cp.load()

        if existing and existing.get('file_path') == str(file_path):
            session_id = existing.get('session_id')
            # Verify session still alive on server
            try:
                r = self.session.get(f"{self.server_url}/api/session/{session_id}/status", timeout=5)
                if r.status_code == 200:
                    server_done = set(r.json().get('received_chunks', []))
                    cp_data = existing
                    resuming = True
                    print(f"[Resume] Resuming session {session_id[:8]}... "
                          f"({len(server_done)} chunks already uploaded)")
                else:
                    resuming = False
                    cp_data = None
            except Exception:
                resuming = False
                cp_data = None
        else:
            resuming = False
            cp_data = None

        # ── Derive keys ──────────────────────────────────────────
        if resuming and cp_data:
            # Recover salt and keys from checkpoint (they were saved encrypted)
            salt = bytes.fromhex(cp_data['salt'])
            master_key = CE.derive_key(password, salt)
            file_key = bytes.fromhex(cp_data['file_key_hex'])
            hmac_key = bytes.fromhex(cp_data['hmac_key_hex'])
            master_nonce = bytes.fromhex(cp_data['master_nonce'])
            file_key_enc = bytes.fromhex(cp_data['file_key_enc'])
            hmac_key_enc = bytes.fromhex(cp_data['hmac_key_enc'])
        else:
            salt = os.urandom(SALT_SIZE)
            master_key = CE.derive_key(password, salt)
            file_key = CE.generate_file_key()
            hmac_key = CE.generate_file_key()
            master_nonce = os.urandom(NONCE_SIZE)
            aesgcm = AESGCM(master_key)
            file_key_enc = aesgcm.encrypt(master_nonce, file_key, b"file-key")
            hmac_key_enc = aesgcm.encrypt(master_nonce, hmac_key, b"hmac-key")

        # ── Read file metadata ───────────────────────────────────
        file_size = os.path.getsize(file_path)
        filename = file_path.name.encode('utf-8')
        num_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE or 1

        # ── Start or resume session ──────────────────────────────
        if not resuming:
            r = self.session.post(f"{self.server_url}/api/session/start", json={
                'filename': file_path.name,
                'num_chunks': num_chunks,
                'file_size': file_size,
            }, timeout=10)
            r.raise_for_status()
            session_id = r.json()['session_id']

            # Save checkpoint
            cp.save({
                'file_path': str(file_path),
                'session_id': session_id,
                'salt': salt.hex(),
                'master_nonce': master_nonce.hex(),
                'file_key_hex': file_key.hex(),
                'hmac_key_hex': hmac_key.hex(),
                'file_key_enc': file_key_enc.hex(),
                'hmac_key_enc': hmac_key_enc.hex(),
                'num_chunks': num_chunks,
                'file_size': file_size,
                'done_chunks': [],
                'started_at': time.time(),
            })
            server_done = set()

        # ── Upload chunks ────────────────────────────────────────
        chunk_metas = []  # (chunk_idx, encrypted_size)

        with open(file_path, 'rb') as f:
            for chunk_idx in range(num_chunks):
                f.seek(chunk_idx * CHUNK_SIZE)
                data = f.read(CHUNK_SIZE)
                if not data:
                    break

                if chunk_idx in server_done:
                    # Already uploaded — ask server for size
                    r = self.session.get(
                        f"{self.server_url}/api/session/{session_id}/chunk/{chunk_idx}/meta",
                        timeout=5
                    )
                    enc_size = r.json().get('size', 0) if r.status_code == 200 else 0
                    chunk_metas.append((chunk_idx, enc_size))
                    if progress_callback:
                        progress_callback('uploading', chunk_idx + 1, num_chunks,
                                          f"Skipped chunk {chunk_idx} (already uploaded)")
                    continue

                encrypted_chunk = CE.encrypt_chunk(data, file_key, chunk_idx)

                r = self.session.post(
                    f"{self.server_url}/api/session/{session_id}/chunk/{chunk_idx}",
                    data=encrypted_chunk,
                    headers={'Content-Type': 'application/octet-stream'},
                    timeout=60
                )
                r.raise_for_status()
                chunk_metas.append((chunk_idx, len(encrypted_chunk)))
                cp.mark_chunk_done(chunk_idx)

                if progress_callback:
                    progress_callback('uploading', chunk_idx + 1, num_chunks,
                                      f"Uploaded chunk {chunk_idx+1}/{num_chunks}")

        # ── Finalize: assemble header + HMAC on server ───────────
        if progress_callback:
            progress_callback('finalizing', 0, 1, "Assembling encrypted file on server...")

        r = self.session.post(f"{self.server_url}/api/session/{session_id}/finalize", json={
            'salt': salt.hex(),
            'master_nonce': master_nonce.hex(),
            'file_key_enc': file_key_enc.hex(),
            'hmac_key_enc': hmac_key_enc.hex(),
            'file_size': file_size,
            'filename': file_path.name,
            'num_chunks': num_chunks,
            'original_hash': CE.compute_file_hash(str(file_path)),
        }, timeout=60)
        r.raise_for_status()
        result = r.json()

        cp.complete()

        if progress_callback:
            progress_callback('complete', 1, 1, "Upload complete!")

        return result


class ResumableDownloader:
    """
    Download with resume — saves partial encrypted blob and resumes byte ranges.
    """

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()

    def download_and_decrypt(self, vault_id: str, password: str, output_path: str,
                              progress_callback: Optional[Callable] = None) -> dict:
        """Download with HTTP Range resume then decrypt."""
        tmp_path = output_path + '.partial'
        checkpoint_path = output_path + '.dl_checkpoint'
        cp = CheckpointManager(checkpoint_path)

        existing = cp.load()
        resume_offset = 0

        if existing and existing.get('vault_id') == vault_id and os.path.exists(tmp_path):
            resume_offset = os.path.getsize(tmp_path)
            print(f"[Resume] Resuming download from byte {resume_offset:,}")

        # ── Download with Range header ────────────────────────────
        headers = {}
        if resume_offset > 0:
            headers['Range'] = f'bytes={resume_offset}-'

        r = self.session.get(
            f"{self.server_url}/api/download/{vault_id}",
            headers=headers, stream=True, timeout=300
        )

        if r.status_code == 416:
            # Range not satisfiable → file fully downloaded
            total_size = resume_offset
        else:
            r.raise_for_status()
            total_size = int(r.headers.get('Content-Length', 0)) + resume_offset

        mode = 'ab' if resume_offset > 0 else 'wb'
        downloaded = resume_offset

        cp.save({'vault_id': vault_id, 'started': time.time(), 'offset': resume_offset})

        with open(tmp_path, mode) as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback:
                    progress_callback('downloading', downloaded, total_size,
                                      f"Downloaded {downloaded:,}/{total_size:,} bytes")

        if progress_callback:
            progress_callback('decrypting', 0, 1, "Decrypting...")

        enc = FileEncryptor()
        meta = enc.decrypt_file(tmp_path, output_path, password)

        # Cleanup
        size = os.path.getsize(tmp_path)
        with open(tmp_path, 'wb') as f:
            f.write(os.urandom(size))
        os.unlink(tmp_path)
        cp.complete()

        if progress_callback:
            progress_callback('complete', 1, 1, "Download and decryption complete!")

        return meta
