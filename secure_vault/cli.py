#!/usr/bin/env python3
"""
SecureVault CLI
================
Command-line interface for all SecureVault operations.

Usage:
  python cli.py encrypt <file> [--output <out>] [--password <pw>]
  python cli.py decrypt <file.svlt> [--output <dir>] [--password <pw>]
  python cli.py upload <file> [--server <url>] [--password <pw>]
  python cli.py download <vault-id> [--server <url>] [--password <pw>] [--output <dir>]
  python cli.py list [--server <url>]
  python cli.py delete <vault-id> [--server <url>]
  python cli.py verify <vault-id> [--server <url>]
  python cli.py info <file.svlt>
  python cli.py server [--port <port>]
  python cli.py gui [--port <port>]
"""

import sys
import os
import argparse
import getpass
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ANSI colors
R  = '\033[0;31m'
G  = '\033[0;32m'
Y  = '\033[0;33m'
B  = '\033[0;34m'
C  = '\033[0;36m'
W  = '\033[1;37m'
DIM = '\033[2m'
RESET = '\033[0m'
BOLD = '\033[1m'


def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║  {W}🔐 SecureVault CLI v2.0.0{C}                           ║
║  {DIM}AES-256-GCM · HMAC-SHA256 · PBKDF2 (600k){C}          ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def fmt(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


def progress_bar(done, total, width=40, label=""):
    if total <= 0:
        return
    pct = min(100, int(100 * done / total))
    filled = int(width * done / total)
    bar = '█' * filled + '░' * (width - filled)
    sys.stdout.write(f"\r  {C}[{bar}]{RESET} {W}{pct:3d}%{RESET} {DIM}{label}{RESET}  ")
    sys.stdout.flush()
    if done >= total:
        print()


def get_password(prompt="Password: ", confirm=False) -> str:
    pw = getpass.getpass(f"{C}  {prompt}{RESET}")
    if confirm:
        pw2 = getpass.getpass(f"{C}  Confirm password: {RESET}")
        if pw != pw2:
            print(f"{R}  ✗ Passwords do not match!{RESET}")
            sys.exit(1)
    return pw


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_encrypt(args):
    """Encrypt a file locally."""
    from core.crypto_engine import FileEncryptor

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"{R}  ✗ File not found: {file_path}{RESET}")
        sys.exit(1)

    output = Path(args.output) if args.output else file_path.with_suffix(file_path.suffix + '.svlt')
    password = args.password or get_password("Encryption password: ", confirm=True)

    print(f"\n{W}  Encrypting:{RESET} {file_path.name}")
    print(f"  {DIM}Size: {fmt(file_path.stat().st_size)} → Output: {output.name}{RESET}")
    print()

    start = time.time()

    def progress(done, total):
        progress_bar(done, total, label=f"{fmt(done)}/{fmt(total)}")

    enc = FileEncryptor()
    try:
        meta = enc.encrypt_file(str(file_path), str(output), password, progress)
    except Exception as e:
        print(f"\n{R}  ✗ Encryption failed: {e}{RESET}")
        sys.exit(1)

    elapsed = time.time() - start
    print(f"\n{G}  ✓ Encrypted successfully!{RESET}")
    print(f"\n  {W}Output:{RESET}       {output}")
    print(f"  {W}Chunks:{RESET}       {meta['num_chunks']} × 1 MB")
    print(f"  {W}Original:{RESET}     {fmt(meta['original_size'])}")
    print(f"  {W}Encrypted:{RESET}    {fmt(meta['encrypted_size'])}")
    print(f"  {W}Overhead:{RESET}     {fmt(meta['encrypted_size'] - meta['original_size'])}")
    print(f"  {W}SHA-256:{RESET}      {meta['original_hash_sha256'][:32]}...")
    print(f"  {W}Time:{RESET}         {elapsed:.2f}s")
    print(f"  {W}Algorithm:{RESET}    AES-256-GCM + HMAC-SHA256 + PBKDF2(600k)\n")


def cmd_decrypt(args):
    """Decrypt a .svlt file locally."""
    from core.crypto_engine import FileEncryptor

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"{R}  ✗ File not found: {file_path}{RESET}")
        sys.exit(1)

    if not str(file_path).endswith('.svlt'):
        print(f"{Y}  ⚠ Warning: file does not end in .svlt{RESET}")

    output_dir = Path(args.output) if args.output else file_path.parent
    password = args.password or get_password("Decryption password: ")

    print(f"\n{W}  Decrypting:{RESET} {file_path.name}")
    print(f"  {DIM}Verifying HMAC-SHA256 integrity...{RESET}\n")

    start = time.time()

    def progress(done, total):
        progress_bar(done, total, label=f"chunk {done}/{total}")

    enc = FileEncryptor()
    try:
        # Determine output path after decrypt (we'll know original filename)
        tmp_out = str(output_dir / ('decrypted_' + file_path.stem))
        meta = enc.decrypt_file(str(file_path), tmp_out, password, progress)

        # Rename to original filename
        orig_name = meta.get('original_filename', file_path.stem)
        final_out = output_dir / orig_name
        if final_out.exists():
            final_out = output_dir / (f"decrypted_{orig_name}")
        Path(tmp_out).rename(final_out)

    except Exception as e:
        print(f"\n{R}  ✗ Decryption failed: {e}{RESET}")
        sys.exit(1)

    elapsed = time.time() - start
    print(f"\n{G}  ✓ Decryption successful!{RESET}")
    print(f"\n  {W}Output file:{RESET}  {final_out}")
    print(f"  {W}Size:{RESET}         {fmt(meta['original_size'])}")
    print(f"  {W}SHA-256:{RESET}      {meta['decrypted_hash_sha256'][:32]}...")
    print(f"  {W}Chunks:{RESET}       {meta['num_chunks']} verified")
    print(f"  {W}Time:{RESET}         {elapsed:.2f}s\n")


def cmd_upload(args):
    """Encrypt and upload to vault server."""
    from client.vault_client import VaultClient

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"{R}  ✗ File not found: {file_path}{RESET}")
        sys.exit(1)

    server = args.server or 'http://localhost:5001'
    password = args.password or get_password("Encryption password: ", confirm=True)

    print(f"\n{W}  Uploading:{RESET} {file_path.name} → {server}")
    print(f"  {DIM}Note: password never leaves your machine{RESET}\n")

    client = VaultClient(server)

    # Health check
    try:
        client.health_check()
    except Exception as e:
        print(f"{R}  ✗ Cannot reach server: {e}{RESET}")
        sys.exit(1)

    start = time.time()

    def progress(stage, done, total, msg=""):
        stages = {'encrypting':'🔐 ENCRYPTING', 'uploading':'⬆ UPLOADING ', 'complete':'✓ COMPLETE  '}
        label = stages.get(stage, stage.upper())
        if total > 0:
            progress_bar(done, total, label=f"{label} {msg}")

    try:
        result = client.upload_file(str(file_path), password, progress)
    except Exception as e:
        print(f"\n{R}  ✗ Upload failed: {e}{RESET}")
        sys.exit(1)

    elapsed = time.time() - start
    rec = result.get('record', {})

    print(f"\n{G}  ✓ Upload complete!{RESET}")
    print(f"\n  {W}Vault ID:{RESET}     {rec.get('vault_id', '?')}")
    print(f"  {W}Filename:{RESET}     {rec.get('original_filename', '?')}")
    print(f"  {W}Encrypted:{RESET}    {fmt(rec.get('encrypted_size', 0))}")
    print(f"  {W}Chunks:{RESET}       {rec.get('num_chunks', '?')}")
    print(f"  {W}Time:{RESET}         {elapsed:.2f}s")
    print(f"\n  {C}Save this Vault ID to download later:{RESET}")
    print(f"  {W}{rec.get('vault_id', '?')}{RESET}\n")


def cmd_download(args):
    """Download and decrypt from vault."""
    from client.vault_client import VaultClient

    vault_id = args.vault_id
    server = args.server or 'http://localhost:5001'
    output_dir = Path(args.output) if args.output else Path('.')
    password = args.password or get_password("Decryption password: ")

    print(f"\n{W}  Downloading:{RESET} {vault_id[:16]}...")
    print(f"  {DIM}Server: {server}{RESET}\n")

    client = VaultClient(server)

    # Get file info first
    try:
        info = client.get_file_info(vault_id)
        print(f"  {DIM}File: {info.get('original_filename','?')} "
              f"({fmt(info.get('original_size',0))}){RESET}\n")
    except Exception:
        pass

    start = time.time()

    def progress(stage, done, total, msg=""):
        stages = {'downloading':'⬇ DOWNLOADING', 'decrypting':'🔓 DECRYPTING ', 'complete':'✓ COMPLETE   '}
        label = stages.get(stage, stage.upper())
        if total > 0:
            progress_bar(done, total, label=label)

    output_path = str(output_dir / 'vault_download_tmp')

    try:
        meta = client.download_and_decrypt(vault_id, password, output_path, progress)
    except Exception as e:
        print(f"\n{R}  ✗ Failed: {e}{RESET}")
        sys.exit(1)

    # Rename to original
    orig_name = meta.get('original_filename', 'downloaded_file')
    final = output_dir / orig_name
    if final.exists():
        final = output_dir / f"vault_{orig_name}"
    Path(output_path).rename(final)

    elapsed = time.time() - start
    print(f"\n{G}  ✓ Decryption verified and saved!{RESET}")
    print(f"\n  {W}Saved to:{RESET}    {final}")
    print(f"  {W}Size:{RESET}        {fmt(meta['original_size'])}")
    print(f"  {W}SHA-256:{RESET}     {meta['decrypted_hash_sha256'][:32]}...")
    print(f"  {W}Time:{RESET}        {elapsed:.2f}s\n")


def cmd_list(args):
    """List vault contents."""
    from client.vault_client import VaultClient

    server = args.server or 'http://localhost:5001'
    client = VaultClient(server)

    try:
        data = client.list_files()
    except Exception as e:
        print(f"{R}  ✗ Cannot reach server: {e}{RESET}")
        sys.exit(1)

    files = data.get('files', [])
    stats = data.get('stats', {})

    print(f"\n{C}  ══ SecureVault Contents ══{RESET}")
    print(f"  Server: {server}")
    print(f"  Files: {stats.get('total_files',0)}  "
          f"Encrypted storage: {fmt(stats.get('total_encrypted_bytes',0))}\n")

    if not files:
        print(f"  {DIM}Vault is empty.{RESET}\n")
        return

    print(f"  {W}{'VAULT ID':38} {'FILENAME':25} {'SIZE':8} {'CHUNKS':6} {'DATE'}{RESET}")
    print(f"  {'─'*38} {'─'*25} {'─'*8} {'─'*6} {'─'*20}")

    for f in files:
        vid = f.get('vault_id', '?')[:36]
        name = f.get('original_filename', '?')[:24]
        size = fmt(f.get('encrypted_size', 0))
        chunks = str(f.get('num_chunks', '?'))
        ts = f.get('upload_timestamp', '?')[:19].replace('T', ' ')
        print(f"  {C}{vid}{RESET}  {W}{name:<25}{RESET}  {size:>8}  {chunks:>6}  {DIM}{ts}{RESET}")

    print()


def cmd_delete(args):
    """Securely delete a vault file."""
    from client.vault_client import VaultClient

    vault_id = args.vault_id
    server = args.server or 'http://localhost:5001'

    if not args.yes:
        confirm = input(f"\n  {Y}Delete {vault_id[:16]}...? This uses 3-pass overwrite. [y/N]{RESET} ")
        if confirm.lower() != 'y':
            print("  Cancelled.")
            return

    client = VaultClient(server)
    try:
        result = client.delete_file(vault_id)
        print(f"\n{G}  ✓ {result.get('message','Deleted')}{RESET}\n")
    except Exception as e:
        print(f"{R}  ✗ Delete failed: {e}{RESET}")
        sys.exit(1)


def cmd_verify(args):
    """Verify encrypted blob integrity."""
    from client.vault_client import VaultClient

    vault_id = args.vault_id
    server = args.server or 'http://localhost:5001'

    print(f"\n{W}  Verifying integrity:{RESET} {vault_id[:16]}...")

    client = VaultClient(server)
    try:
        result = client.verify_file(vault_id)
    except Exception as e:
        print(f"{R}  ✗ Verify failed: {e}{RESET}")
        sys.exit(1)

    status = result.get('status', '?')
    ok = result.get('ok', False)

    if ok:
        print(f"\n{G}  ✓ INTEGRITY OK — blob hash matches{RESET}")
    else:
        print(f"\n{R}  ✗ INTEGRITY FAIL — blob has been TAMPERED WITH!{RESET}")

    print(f"\n  {W}Status:{RESET}   {status}")
    print(f"  {W}Expected:{RESET} {result.get('stored_hash','?')[:32]}...")
    print(f"  {W}Current:{RESET}  {result.get('current_hash','?')[:32]}...")
    print(f"  {W}Checked:{RESET}  {result.get('checked_at','?')}\n")

    if not ok:
        sys.exit(1)


def cmd_info(args):
    """Show metadata of a .svlt encrypted file without decrypting."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"{R}  ✗ File not found{RESET}")
        sys.exit(1)

    with open(file_path, 'rb') as f:
        raw = f.read(200)  # header is in first ~200 bytes

    import struct

    if raw[:4] != b'SVLT':
        print(f"{R}  ✗ Not a SecureVault file (wrong magic bytes){RESET}")
        sys.exit(1)

    version = raw[4]
    # Skip salt(32) + master_nonce(12) + file_key_enc(48) + hmac_key_enc(48) = 140
    pos = 5 + 32 + 12 + 48 + 48
    orig_size = struct.unpack('>Q', raw[pos:pos+8])[0]; pos += 8
    fname_len = struct.unpack('>H', raw[pos:pos+2])[0]; pos += 2
    filename = raw[pos:pos+fname_len].decode('utf-8', errors='replace')
    pos += fname_len
    num_chunks = struct.unpack('>I', raw[pos:pos+4])[0]

    file_size = file_path.stat().st_size
    overhead = file_size - orig_size

    print(f"\n{C}  ══ SecureVault File Info ══{RESET}")
    print(f"\n  {W}File:{RESET}         {file_path}")
    print(f"  {W}Format:{RESET}       SVLT v{version}")
    print(f"  {W}Filename:{RESET}     {filename}")
    print(f"  {W}Original size:{RESET} {fmt(orig_size)} ({orig_size:,} bytes)")
    print(f"  {W}Encrypted size:{RESET} {fmt(file_size)} ({file_size:,} bytes)")
    print(f"  {W}Overhead:{RESET}     {fmt(overhead)}")
    print(f"  {W}Chunks:{RESET}       {num_chunks} × 1 MB")
    print(f"\n  {DIM}Encryption: AES-256-GCM | Integrity: HMAC-SHA256 | KDF: PBKDF2-SHA256{RESET}")
    print(f"  {DIM}Salt: 32 bytes (random) | Nonce: 12 bytes (random+counter){RESET}\n")


def cmd_server(args):
    """Start the vault server."""
    port = args.port or 5001
    print(f"\n{C}  Starting SecureVault Server on port {port}...{RESET}\n")
    from server.server import app
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)


def cmd_gui(args):
    """Start the GUI app."""
    port = args.port or 5000
    print(f"\n{C}  Starting SecureVault GUI on port {port}...{RESET}")
    print(f"  {W}Open: http://localhost:{port}{RESET}\n")
    from app import app
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)


# ── Argument Parser ────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        prog='securevault',
        description='SecureVault — Encrypted File Storage CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', metavar='COMMAND')

    # encrypt
    p = sub.add_parser('encrypt', help='Encrypt a file locally')
    p.add_argument('file', help='File to encrypt')
    p.add_argument('--output', '-o', help='Output .svlt path')
    p.add_argument('--password', '-p', help='Password (omit for prompt)')

    # decrypt
    p = sub.add_parser('decrypt', help='Decrypt a .svlt file locally')
    p.add_argument('file', help='.svlt file to decrypt')
    p.add_argument('--output', '-o', help='Output directory')
    p.add_argument('--password', '-p', help='Password (omit for prompt)')

    # upload
    p = sub.add_parser('upload', help='Encrypt & upload to vault server')
    p.add_argument('file', help='File to upload')
    p.add_argument('--server', '-s', help='Server URL (default: http://localhost:5001)')
    p.add_argument('--password', '-p', help='Password')

    # download
    p = sub.add_parser('download', help='Download & decrypt from vault')
    p.add_argument('vault_id', help='Vault ID (UUID)')
    p.add_argument('--server', '-s', help='Server URL')
    p.add_argument('--password', '-p', help='Password')
    p.add_argument('--output', '-o', help='Output directory')

    # list
    p = sub.add_parser('list', help='List vault contents', aliases=['ls'])
    p.add_argument('--server', '-s', help='Server URL')

    # delete
    p = sub.add_parser('delete', help='Securely delete a vault file', aliases=['rm'])
    p.add_argument('vault_id', help='Vault ID to delete')
    p.add_argument('--server', '-s', help='Server URL')
    p.add_argument('--yes', '-y', action='store_true', help='Skip confirmation')

    # verify
    p = sub.add_parser('verify', help='Verify file integrity')
    p.add_argument('vault_id', help='Vault ID to verify')
    p.add_argument('--server', '-s', help='Server URL')

    # info
    p = sub.add_parser('info', help='Show .svlt file metadata')
    p.add_argument('file', help='.svlt file to inspect')

    # server
    p = sub.add_parser('server', help='Start vault server')
    p.add_argument('--port', type=int, default=5001)

    # gui
    p = sub.add_parser('gui', help='Start GUI web app')
    p.add_argument('--port', type=int, default=5000)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(f"\n  {DIM}Example: python cli.py encrypt myfile.pdf{RESET}\n")
        sys.exit(0)

    cmd = args.command
    dispatch = {
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'upload': cmd_upload,
        'download': cmd_download,
        'list': cmd_list, 'ls': cmd_list,
        'delete': cmd_delete, 'rm': cmd_delete,
        'verify': cmd_verify,
        'info': cmd_info,
        'server': cmd_server,
        'gui': cmd_gui,
    }

    fn = dispatch.get(cmd)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
