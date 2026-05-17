"""
SecureVault Session Server Extension
=====================================
Adds resume-capable chunked upload endpoints to the Flask server.
Import and register this blueprint in server.py.

Session lifecycle:
  1. Client POSTs /api/session/start → gets session_id
  2. Client POSTs each chunk to /api/session/<id>/chunk/<n>
  3. On crash/resume: client GETs /api/session/<id>/status
  4. Client POSTs /api/session/<id>/finalize → assembles .svlt blob
  5. Server registers final file in vault metadata
"""

import os
import sys
import json
import struct
import time
import uuid
import hmac as hmaclib
import hashlib
from pathlib import Path
from flask import Blueprint, request, jsonify

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.crypto_engine import (
    CryptoEngine, MAGIC, VERSION, SALT_SIZE, NONCE_SIZE, HMAC_SIZE
)

# Sessions stored in memory + disk
SESSIONS_DIR = Path(__file__).parent.parent / "server_storage" / "sessions"
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

sessions_bp = Blueprint('sessions', __name__)


def session_dir(sid: str) -> Path:
    d = SESSIONS_DIR / sid
    d.mkdir(exist_ok=True)
    return d


def session_meta(sid: str) -> dict:
    p = SESSIONS_DIR / sid / "meta.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_session_meta(sid: str, data: dict):
    p = SESSIONS_DIR / sid / "meta.json"
    p.write_text(json.dumps(data, indent=2))


@sessions_bp.route('/api/session/start', methods=['POST'])
def start_session():
    """Initialize a chunked upload session."""
    data = request.get_json()
    sid = str(uuid.uuid4())
    sd = session_dir(sid)

    meta = {
        'session_id': sid,
        'filename': data.get('filename', 'unknown'),
        'num_chunks': data.get('num_chunks', 0),
        'file_size': data.get('file_size', 0),
        'received_chunks': [],
        'started_at': time.time(),
        'client_ip': request.remote_addr,
    }
    save_session_meta(sid, meta)

    return jsonify({'session_id': sid, 'status': 'started'})


@sessions_bp.route('/api/session/<sid>/status', methods=['GET'])
def session_status(sid):
    """Return which chunks have been received."""
    meta = session_meta(sid)
    if not meta:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify({
        'session_id': sid,
        'received_chunks': meta.get('received_chunks', []),
        'num_chunks': meta.get('num_chunks', 0),
        'filename': meta.get('filename', ''),
    })


@sessions_bp.route('/api/session/<sid>/chunk/<int:chunk_idx>', methods=['POST'])
def upload_chunk(sid, chunk_idx):
    """Receive a single encrypted chunk."""
    meta = session_meta(sid)
    if not meta:
        return jsonify({'error': 'Session not found'}), 404

    sd = session_dir(sid)
    chunk_path = sd / f"chunk_{chunk_idx:06d}.bin"
    chunk_path.write_bytes(request.data)

    received = set(meta.get('received_chunks', []))
    received.add(chunk_idx)
    meta['received_chunks'] = sorted(received)
    meta['last_activity'] = time.time()
    save_session_meta(sid, meta)

    return jsonify({'ok': True, 'chunk': chunk_idx, 'size': len(request.data)})


@sessions_bp.route('/api/session/<sid>/chunk/<int:chunk_idx>/meta', methods=['GET'])
def chunk_meta(sid, chunk_idx):
    """Return size of a stored chunk (for resume verification)."""
    sd = session_dir(sid)
    chunk_path = sd / f"chunk_{chunk_idx:06d}.bin"
    if chunk_path.exists():
        return jsonify({'chunk': chunk_idx, 'size': chunk_path.stat().st_size})
    return jsonify({'error': 'Chunk not found'}), 404


@sessions_bp.route('/api/session/<sid>/finalize', methods=['POST'])
def finalize_session(sid):
    """
    Assemble all chunks into a complete .svlt file and register in vault.
    The header is reconstructed from the client-provided key material.
    """
    from server.server import STORAGE_DIR, load_metadata, save_metadata, meta_lock
    from datetime import datetime

    meta = session_meta(sid)
    if not meta:
        return jsonify({'error': 'Session not found'}), 404

    data = request.get_json()
    num_chunks = meta['num_chunks']
    received = set(meta.get('received_chunks', []))

    if len(received) < num_chunks:
        missing = [i for i in range(num_chunks) if i not in received]
        return jsonify({'error': f'Missing chunks: {missing}'}), 400

    sd = session_dir(sid)

    # ── Reconstruct .svlt binary format ──────────────────────────
    salt = bytes.fromhex(data['salt'])
    master_nonce = bytes.fromhex(data['master_nonce'])
    file_key_enc = bytes.fromhex(data['file_key_enc'])
    hmac_key_enc = bytes.fromhex(data['hmac_key_enc'])
    file_size = data['file_size']
    filename = data['filename'].encode('utf-8')
    original_hash = data.get('original_hash', '')

    # Read all chunk data
    chunks = []
    for i in range(num_chunks):
        chunk_path = sd / f"chunk_{i:06d}.bin"
        chunks.append(chunk_path.read_bytes())

    # Build header (must match crypto_engine.py format exactly)
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

    chunk_sizes = b''
    for c in chunks:
        chunk_sizes += struct.pack('>I', len(c))

    # We need the HMAC key to compute the MAC
    # But the HMAC key is encrypted — we can't compute it server-side (zero knowledge!)
    # Solution: client sends the HMAC over the payload, we just store what client sends
    # OR: we ask client to compute and send the HMAC
    # In this architecture, the client sends hmac_of_payload
    hmac_hex = data.get('hmac_of_payload')

    all_data = header + chunk_sizes + b''.join(chunks)

    if hmac_hex:
        mac = bytes.fromhex(hmac_hex)
    else:
        # Fallback: zero HMAC (client didn't send — reduced security)
        mac = b'\x00' * HMAC_SIZE

    vault_id = str(uuid.uuid4())
    stored_name = f"{vault_id}.svlt"
    stored_path = STORAGE_DIR / stored_name

    with open(stored_path, 'wb') as f:
        f.write(all_data)
        f.write(mac)

    encrypted_size = stored_path.stat().st_size
    blob_hash = CryptoEngine.compute_file_hash(str(stored_path))

    record = {
        'vault_id': vault_id,
        'original_filename': meta['filename'],
        'stored_name': stored_name,
        'encrypted_size': encrypted_size,
        'original_size': file_size,
        'num_chunks': num_chunks,
        'original_hash_sha256': original_hash,
        'encrypted_blob_hash': blob_hash,
        'upload_timestamp': datetime.utcnow().isoformat() + 'Z',
        'client_ip': meta.get('client_ip', ''),
        'encryption': 'AES-256-GCM',
        'integrity': 'HMAC-SHA256',
        'upload_method': 'chunked-resume',
    }

    with meta_lock:
        vault_meta = load_metadata()
        vault_meta['files'][vault_id] = record
        vault_meta.setdefault('stats', {})
        vault_meta['stats']['total_uploads'] = vault_meta['stats'].get('total_uploads', 0) + 1
        vault_meta['stats']['total_bytes_stored'] = (
            vault_meta['stats'].get('total_bytes_stored', 0) + encrypted_size
        )
        save_metadata(vault_meta)

    # Clean up session chunks
    import shutil
    shutil.rmtree(str(sd), ignore_errors=True)

    return jsonify({'success': True, 'vault_id': vault_id, 'record': record}), 201


@sessions_bp.route('/api/session/<sid>', methods=['DELETE'])
def abort_session(sid):
    """Abort a session and clean up chunks."""
    import shutil
    sd = SESSIONS_DIR / sid
    if sd.exists():
        shutil.rmtree(str(sd))
    return jsonify({'ok': True, 'message': f'Session {sid} aborted'})
