"""
SecureVault GUI App
====================
Flask app serving the beautiful frontend and providing a local API proxy.
Runs encryption/decryption in-process so the GUI can show real-time progress.
"""

import os
import sys
import json
import threading
import subprocess
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import tempfile

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from core.crypto_engine import FileEncryptor, CryptoEngine
from client.vault_client import VaultClient

app = Flask(__name__, static_folder=str(BASE_DIR / 'static'), template_folder=str(BASE_DIR / 'templates'))
app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024

VAULT_SERVER = os.environ.get('VAULT_SERVER', 'http://localhost:5001')
DOWNLOAD_DIR = BASE_DIR / 'downloads'
DOWNLOAD_DIR.mkdir(exist_ok=True)

encryptor = FileEncryptor()

# Progress tracking
progress_store = {}
progress_lock = threading.Lock()

def set_progress(op_id, stage, done, total, message="", error=None):
    with progress_lock:
        progress_store[op_id] = {
            "stage": stage,
            "done": done,
            "total": total,
            "pct": int(100 * done / total) if total > 0 else 0,
            "message": message,
            "error": error,
            "complete": stage == "complete",
        }

@app.route('/')
def index():
    return send_from_directory(str(BASE_DIR / 'templates'), 'index.html')

@app.route('/api/health', methods=['GET'])
def health():
    try:
        client = VaultClient(VAULT_SERVER)
        result = client.health_check()
        result['gui_version'] = '2.0.0'
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "offline", "error": str(e)}), 503

@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        client = VaultClient(VAULT_SERVER)
        return jsonify(client.list_files())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload():
    """Handle file upload with local encryption."""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    password = request.form.get('password', '')
    op_id = request.form.get('op_id', 'upload')

    if not password:
        return jsonify({"error": "Password required"}), 400

    # Save uploaded file to temp
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        file.save(tmp.name)
        tmp_input = tmp.name

    try:
        set_progress(op_id, "encrypting", 0, 100, "Encrypting file locally...")

        def progress(stage, done, total):
            if stage == "encrypting":
                pct = int(100 * done / total) if total > 0 else 0
                set_progress(op_id, "encrypting", pct, 100, f"Encrypting... {pct}%")
            elif stage == "uploading":
                pct = int(100 * done / total) if total > 0 else 50
                set_progress(op_id, "uploading", pct, 100, f"Uploading encrypted blob... {pct}%")

        client = VaultClient(VAULT_SERVER)
        result = client.upload_file(tmp_input, password, progress)

        set_progress(op_id, "complete", 100, 100, "Upload complete!")
        return jsonify({"success": True, "result": result})

    except Exception as e:
        set_progress(op_id, "error", 0, 1, "", error=str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(tmp_input):
            # Wipe temp plaintext
            size = os.path.getsize(tmp_input)
            with open(tmp_input, 'wb') as f:
                f.write(os.urandom(size))
            os.unlink(tmp_input)

@app.route('/api/download/<vault_id>', methods=['POST'])
def download(vault_id):
    """Download and decrypt a file."""
    data = request.get_json()
    password = data.get('password', '')
    op_id = data.get('op_id', 'download')

    if not password:
        return jsonify({"error": "Password required"}), 400

    try:
        set_progress(op_id, "downloading", 0, 100, "Downloading from vault...")

        # Get original filename
        client = VaultClient(VAULT_SERVER)
        info = client.get_file_info(vault_id)
        original_name = info.get('original_filename', f'{vault_id}.bin')

        output_path = str(DOWNLOAD_DIR / original_name)

        def progress(stage, done, total):
            if stage == "downloading":
                pct = int(100 * done / total) if total > 0 else 30
                set_progress(op_id, "downloading", pct, 100, f"Downloading... {pct}%")
            elif stage == "decrypting":
                pct = int(100 * done / total) if total > 0 else 70
                set_progress(op_id, "decrypting", pct, 100, f"Decrypting... {pct}%")

        meta = client.download_and_decrypt(vault_id, password, output_path, progress)
        set_progress(op_id, "complete", 100, 100, "Decryption complete!")

        return jsonify({
            "success": True,
            "filename": original_name,
            "meta": meta,
            "download_url": f"/api/serve/{original_name}"
        })

    except Exception as e:
        set_progress(op_id, "error", 0, 1, "", error=str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/api/serve/<filename>')
def serve_file(filename):
    """Serve decrypted file for browser download."""
    return send_file(
        str(DOWNLOAD_DIR / filename),
        as_attachment=True,
        download_name=filename
    )

@app.route('/api/delete/<vault_id>', methods=['DELETE'])
def delete_file(vault_id):
    try:
        client = VaultClient(VAULT_SERVER)
        return jsonify(client.delete_file(vault_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify/<vault_id>', methods=['GET'])
def verify_file(vault_id):
    try:
        client = VaultClient(VAULT_SERVER)
        return jsonify(client.verify_file(vault_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/progress/<op_id>', methods=['GET'])
def get_progress(op_id):
    with progress_lock:
        return jsonify(progress_store.get(op_id, {"stage": "idle", "pct": 0}))

@app.route('/api/encrypt-local', methods=['POST'])
def encrypt_local():
    """Encrypt a file locally and return it as download."""
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    if not password:
        return jsonify({"error": "Password required"}), 400

    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp_in:
        file.save(tmp_in.name)
        tmp_input = tmp_in.name

    output_path = tmp_input + '.svlt'

    try:
        meta = encryptor.encrypt_file(tmp_input, output_path, password)
        return send_file(
            output_path,
            as_attachment=True,
            download_name=f"{file.filename}.svlt",
            mimetype='application/octet-stream'
        )
    finally:
        if os.path.exists(tmp_input):
            os.unlink(tmp_input)

@app.route('/api/decrypt-local', methods=['POST'])
def decrypt_local():
    """Decrypt a .svlt file locally."""
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files['file']
    password = request.form.get('password', '')

    with tempfile.NamedTemporaryFile(delete=False, suffix='.svlt') as tmp_in:
        file.save(tmp_in.name)
        tmp_input = tmp_in.name

    # Determine output filename
    orig_name = file.filename
    if orig_name.endswith('.svlt'):
        orig_name = orig_name[:-5]

    output_path = tmp_input + '_decrypted_' + orig_name

    try:
        meta = encryptor.decrypt_file(tmp_input, output_path, password)
        filename = meta.get('original_filename', orig_name)
        return send_file(
            output_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if os.path.exists(tmp_input):
            os.unlink(tmp_input)

if __name__ == '__main__':
    print("\n╔══════════════════════════════════════════╗")
    print("║  🔐 SecureVault GUI — Starting...        ║")
    print("║  Open: http://localhost:5000             ║")
    print("╚══════════════════════════════════════════╝\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
