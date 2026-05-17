"""
SecureVault Server
==================
Flask-based encrypted file storage server.
Handles upload, download, listing, and deletion of encrypted files.
All files stored encrypted at rest — server never sees plaintext.
"""

import os
import sys
import json
import time
import uuid
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.crypto_engine import FileEncryptor, RSAKeyManager, CryptoEngine, CHUNK_SIZE
from flask import Response

# ── Configuration ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
STORAGE_DIR = BASE_DIR / "server_storage"
KEY_DIR = BASE_DIR / "keys"
METADATA_FILE = STORAGE_DIR / "vault_metadata.json"
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE + 10 * 1024 * 1024

# Register resume/chunked-upload blueprint
from server.session_routes import sessions_bp
app.register_blueprint(sessions_bp)

# Thread lock for metadata
meta_lock = threading.Lock()

# ── Metadata Store ─────────────────────────────────────────────────────────────
def load_metadata() -> dict:
    if METADATA_FILE.exists():
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    return {"files": {}, "stats": {"total_uploads": 0, "total_bytes_stored": 0}}

def save_metadata(meta: dict):
    with open(METADATA_FILE, 'w') as f:
        json.dump(meta, f, indent=2)

def get_server_stats() -> dict:
    meta = load_metadata()
    files = meta.get("files", {})
    total_encrypted = sum(f.get("encrypted_size", 0) for f in files.values())
    return {
        "total_files": len(files),
        "total_encrypted_bytes": total_encrypted,
        "total_uploads_ever": meta.get("stats", {}).get("total_uploads", 0),
        "server_version": "2.0.0",
        "encryption": "AES-256-GCM",
        "integrity": "HMAC-SHA256",
        "kdf": "PBKDF2-SHA256 (600k iterations)"
    }

# ── Server RSA Keys ────────────────────────────────────────────────────────────
def init_server_keys():
    priv_path = KEY_DIR / "server_private.pem"
    pub_path = KEY_DIR / "server_public.pem"
    if not priv_path.exists():
        print("[SecureVault] Generating RSA-2048 server key pair...")
        RSAKeyManager.generate_keypair(str(KEY_DIR))
        print("[SecureVault] Server keys generated.")
    return pub_path.read_text()

SERVER_PUBLIC_KEY = init_server_keys()

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    """Server health and capability check."""
    return jsonify({
        "status": "online",
        "service": "SecureVault Encrypted Storage",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **get_server_stats()
    })

@app.route('/api/pubkey', methods=['GET'])
def get_public_key():
    """Return server RSA public key for client-side key wrapping."""
    return jsonify({"public_key": SERVER_PUBLIC_KEY})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Upload a pre-encrypted file to the vault.
    Client encrypts locally; server stores encrypted blob.
    The server NEVER receives the password.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Parse metadata from form
    try:
        client_meta = json.loads(request.form.get('metadata', '{}'))
    except Exception:
        client_meta = {}

    # Generate unique vault ID
    vault_id = str(uuid.uuid4())
    original_name = secure_filename(file.filename)
    stored_name = f"{vault_id}.svlt"
    stored_path = STORAGE_DIR / stored_name

    # Save encrypted blob
    file.save(str(stored_path))
    encrypted_size = stored_path.stat().st_size

    # Compute hash of stored blob for integrity record
    blob_hash = CryptoEngine.compute_file_hash(str(stored_path))

    # Store metadata
    record = {
        "vault_id": vault_id,
        "original_filename": client_meta.get("original_filename", original_name),
        "stored_name": stored_name,
        "encrypted_size": encrypted_size,
        "original_size": client_meta.get("original_size", 0),
        "num_chunks": client_meta.get("num_chunks", 0),
        "original_hash_sha256": client_meta.get("original_hash_sha256", ""),
        "encrypted_blob_hash": blob_hash,
        "upload_timestamp": datetime.utcnow().isoformat() + "Z",
        "client_ip": request.remote_addr,
        "encryption": "AES-256-GCM",
        "integrity": "HMAC-SHA256",
    }

    with meta_lock:
        meta = load_metadata()
        meta["files"][vault_id] = record
        meta.setdefault("stats", {})
        meta["stats"]["total_uploads"] = meta["stats"].get("total_uploads", 0) + 1
        meta["stats"]["total_bytes_stored"] = (
            meta["stats"].get("total_bytes_stored", 0) + encrypted_size
        )
        save_metadata(meta)

    return jsonify({
        "success": True,
        "vault_id": vault_id,
        "message": f"File encrypted and stored securely",
        "record": record
    }), 201

@app.route('/api/files', methods=['GET'])
def list_files():
    """List all files in the vault."""
    meta = load_metadata()
    files = list(meta.get("files", {}).values())
    # Sort by upload time descending
    files.sort(key=lambda x: x.get("upload_timestamp", ""), reverse=True)
    return jsonify({
        "files": files,
        "count": len(files),
        "stats": get_server_stats()
    })

@app.route('/api/download/<vault_id>', methods=['GET'])
def download_file(vault_id: str):
    """
    Download encrypted file blob — supports HTTP Range requests for resume.
    """
    meta = load_metadata()
    record = meta.get("files", {}).get(vault_id)

    if not record:
        return jsonify({"error": "File not found in vault"}), 404

    stored_path = STORAGE_DIR / record["stored_name"]
    if not stored_path.exists():
        return jsonify({"error": "Encrypted blob missing from storage"}), 500

    # Integrity check before sending
    current_hash = CryptoEngine.compute_file_hash(str(stored_path))
    if current_hash != record.get("encrypted_blob_hash", ""):
        return jsonify({"error": "INTEGRITY ERROR: Blob hash mismatch — possible tampering!"}), 500

    file_size = stored_path.stat().st_size
    range_header = request.headers.get('Range')

    if range_header:
        # Parse "bytes=START-END"
        try:
            byte_range = range_header.replace('bytes=', '')
            start_str, end_str = byte_range.split('-')
            start = int(start_str)
            end = int(end_str) if end_str else file_size - 1
        except Exception:
            return jsonify({"error": "Invalid Range header"}), 400

        if start >= file_size:
            return Response(status=416, headers={'Content-Range': f'bytes */{file_size}'})

        end = min(end, file_size - 1)
        length = end - start + 1

        def generate_range():
            with open(stored_path, 'rb') as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    yield chunk

        headers = {
            'Content-Range': f'bytes {start}-{end}/{file_size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(length),
            'Content-Disposition': f'attachment; filename="{record["original_filename"]}.svlt"',
            'Content-Type': 'application/octet-stream',
        }
        return Response(generate_range(), status=206, headers=headers)

    # Full file download
    def generate_full():
        with open(stored_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                yield chunk

    headers = {
        'Accept-Ranges': 'bytes',
        'Content-Length': str(file_size),
        'Content-Disposition': f'attachment; filename="{record["original_filename"]}.svlt"',
        'Content-Type': 'application/octet-stream',
    }
    return Response(generate_full(), status=200, headers=headers)

@app.route('/api/file/<vault_id>', methods=['GET'])
def get_file_info(vault_id: str):
    """Get metadata for a specific file."""
    meta = load_metadata()
    record = meta.get("files", {}).get(vault_id)
    if not record:
        return jsonify({"error": "File not found"}), 404
    return jsonify(record)

@app.route('/api/delete/<vault_id>', methods=['DELETE'])
def delete_file(vault_id: str):
    """Securely delete a file from the vault."""
    with meta_lock:
        meta = load_metadata()
        record = meta.get("files", {}).get(vault_id)
        
        if not record:
            return jsonify({"error": "File not found"}), 404

        stored_path = STORAGE_DIR / record["stored_name"]
        
        # Secure deletion: overwrite before unlink
        if stored_path.exists():
            size = stored_path.stat().st_size
            with open(str(stored_path), 'wb') as f:
                # 3-pass overwrite (simplified DoD 5220.22-M)
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            stored_path.unlink()

        del meta["files"][vault_id]
        save_metadata(meta)

    return jsonify({"success": True, "message": f"File {vault_id} securely deleted (3-pass overwrite)"})

@app.route('/api/verify/<vault_id>', methods=['GET'])
def verify_file_integrity(vault_id: str):
    """Verify encrypted blob integrity on-demand."""
    meta = load_metadata()
    record = meta.get("files", {}).get(vault_id)
    if not record:
        return jsonify({"error": "File not found"}), 404

    stored_path = STORAGE_DIR / record["stored_name"]
    if not stored_path.exists():
        return jsonify({"status": "missing", "ok": False}), 200

    current_hash = CryptoEngine.compute_file_hash(str(stored_path))
    expected_hash = record.get("encrypted_blob_hash", "")
    ok = current_hash == expected_hash

    return jsonify({
        "vault_id": vault_id,
        "status": "intact" if ok else "TAMPERED",
        "ok": ok,
        "stored_hash": expected_hash,
        "current_hash": current_hash,
        "checked_at": datetime.utcnow().isoformat() + "Z"
    })

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return '', 200

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🔐 SecureVault Server v2.0.0")
    print("  Encrypted File Storage System")
    print("="*60)
    print(f"  Storage: {STORAGE_DIR}")
    print(f"  Encryption: AES-256-GCM")
    print(f"  Integrity: HMAC-SHA256")
    print(f"  KDF: PBKDF2-SHA256 (600,000 iterations)")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
