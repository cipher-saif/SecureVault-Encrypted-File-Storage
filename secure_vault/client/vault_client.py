"""
SecureVault Client Library
===========================
Handles local encryption/decryption and communication with the vault server.
The password NEVER leaves the client machine.
"""

import os
import sys
import json
import time
import tempfile
import requests
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.crypto_engine import FileEncryptor, CryptoEngine

DEFAULT_SERVER = "http://localhost:5001"
TIMEOUT = 60  # seconds


class VaultClient:
    """Client for interacting with the SecureVault server."""

    def __init__(self, server_url: str = DEFAULT_SERVER):
        self.server_url = server_url.rstrip('/')
        self.encryptor = FileEncryptor()
        self.session = requests.Session()

    def health_check(self) -> dict:
        """Check server health and get capabilities."""
        try:
            r = self.session.get(f"{self.server_url}/api/health", timeout=5)
            r.raise_for_status()
            return r.json()
        except requests.ConnectionError:
            raise ConnectionError(f"Cannot connect to vault server at {self.server_url}")
        except Exception as e:
            raise RuntimeError(f"Health check failed: {e}")

    def get_server_public_key(self) -> str:
        """Retrieve server's RSA public key."""
        r = self.session.get(f"{self.server_url}/api/pubkey", timeout=5)
        r.raise_for_status()
        return r.json()["public_key"]

    def upload_file(
        self,
        file_path: str,
        password: str,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Encrypt file locally, then upload encrypted blob to server.
        Password stays on client — server sees only ciphertext.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Encrypt to temp file
        with tempfile.NamedTemporaryFile(suffix='.svlt', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            def encrypt_progress(done, total):
                if progress_callback:
                    progress_callback("encrypting", done, total)

            # Step 1: Encrypt locally
            meta = self.encryptor.encrypt_file(
                str(file_path), tmp_path, password, encrypt_progress
            )

            if progress_callback:
                progress_callback("uploading", 0, 1)

            # Step 2: Upload encrypted blob
            encrypted_size = os.path.getsize(tmp_path)

            def upload_generator():
                with open(tmp_path, 'rb') as f:
                    uploaded = 0
                    while chunk := f.read(65536):
                        uploaded += len(chunk)
                        if progress_callback:
                            progress_callback("uploading", uploaded, encrypted_size)
                        yield chunk

            with open(tmp_path, 'rb') as f:
                r = self.session.post(
                    f"{self.server_url}/api/upload",
                    files={'file': (f"{file_path.name}.svlt", f, 'application/octet-stream')},
                    data={'metadata': json.dumps(meta)},
                    timeout=300
                )
            r.raise_for_status()
            result = r.json()
            result['local_meta'] = meta
            return result

        finally:
            if os.path.exists(tmp_path):
                # Securely wipe temp file
                size = os.path.getsize(tmp_path)
                with open(tmp_path, 'wb') as f:
                    f.write(os.urandom(size))
                os.unlink(tmp_path)

    def download_and_decrypt(
        self,
        vault_id: str,
        password: str,
        output_path: str,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Download encrypted blob and decrypt locally.
        Password stays on client.
        """
        with tempfile.NamedTemporaryFile(suffix='.svlt', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Step 1: Download encrypted blob
            r = self.session.get(
                f"{self.server_url}/api/download/{vault_id}",
                stream=True,
                timeout=300
            )
            r.raise_for_status()

            total_size = int(r.headers.get('content-length', 0))
            downloaded = 0

            with open(tmp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback("downloading", downloaded, total_size)

            if progress_callback:
                progress_callback("decrypting", 0, 1)

            # Step 2: Decrypt locally
            def decrypt_progress(done, total):
                if progress_callback:
                    progress_callback("decrypting", done, total)

            meta = self.encryptor.decrypt_file(tmp_path, output_path, password, decrypt_progress)

            if progress_callback:
                progress_callback("complete", 1, 1)

            return meta

        finally:
            if os.path.exists(tmp_path):
                size = os.path.getsize(tmp_path)
                with open(tmp_path, 'wb') as f:
                    f.write(os.urandom(size))
                os.unlink(tmp_path)

    def list_files(self) -> dict:
        """List all files in the vault."""
        r = self.session.get(f"{self.server_url}/api/files", timeout=10)
        r.raise_for_status()
        return r.json()

    def delete_file(self, vault_id: str) -> dict:
        """Securely delete a file from the vault."""
        r = self.session.delete(f"{self.server_url}/api/delete/{vault_id}", timeout=10)
        r.raise_for_status()
        return r.json()

    def verify_file(self, vault_id: str) -> dict:
        """Verify encrypted blob integrity."""
        r = self.session.get(f"{self.server_url}/api/verify/{vault_id}", timeout=15)
        r.raise_for_status()
        return r.json()

    def get_file_info(self, vault_id: str) -> dict:
        """Get metadata for a specific file."""
        r = self.session.get(f"{self.server_url}/api/file/{vault_id}", timeout=10)
        r.raise_for_status()
        return r.json()
