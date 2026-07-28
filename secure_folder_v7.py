import os
import json
import secrets
from pathlib import Path
from functools import wraps
import threading
import webview # pyright: ignore[reportMissingImports]
import time

from flask import Flask, request, jsonify, session, send_from_directory # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives import hashes # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore[reportMissingImports]
import bcrypt # type: ignore[reportMissingImports]

# ---------- Configuration ----------
# BASE_VAULT = Path("C:/SecureVault")          # default user vault root
ADMIN_KEY_FILE = Path("admin_key.bin")       # stores the admin's encryption key

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

USERS_FILE_ENC = Path("users.json.enc")
USERS_FILE_PLAIN = Path("users.json")

session_keys = {}              # token → derived key (per session)
users_cache = None             # decrypted user database (always loaded after first admin)
admin_key = None               # permanent admin key (loaded from file at startup)

# NEW: global vault folder, set by admin
vault_folder: Path | None = None
VAULT_FOLDER_FILE = Path("vault_folder.txt")   # persist across restarts

def load_vault_folder():
    global vault_folder
    if VAULT_FOLDER_FILE.exists():
        vault_folder = Path(VAULT_FOLDER_FILE.read_text().strip())
    else:
        vault_folder = None

def save_vault_folder(path: Path):
    VAULT_FOLDER_FILE.write_text(str(path))
    global vault_folder
    vault_folder = path

# ---------- Admin key persistence ----------
def load_admin_key():
    global admin_key
    if ADMIN_KEY_FILE.exists():
        admin_key = ADMIN_KEY_FILE.read_bytes()
        return True
    return False

def save_admin_key(key: bytes):
    ADMIN_KEY_FILE.write_bytes(key)
    global admin_key
    admin_key = key

# ---------- Crypto helpers ----------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_data(payload: bytes, key: bytes) -> bytes:
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ---------- FEK wrapping (was missing!) ----------
def wrap_fek(fek: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    wrapped = aesgcm.encrypt(nonce, fek, None)
    return {"nonce": nonce.hex(), "wrapped_fek": wrapped.hex()}

def unwrap_fek(entry: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(entry["nonce"])
    wrapped = bytes.fromhex(entry["wrapped_fek"])
    return aesgcm.decrypt(nonce, wrapped, None)

# ---------- User DB encryption / decryption ----------
def save_users_encrypted(users_dict: dict, key: bytes):
    data = json.dumps(users_dict).encode()
    USERS_FILE_ENC.write_bytes(encrypt_data(data, key))
    if USERS_FILE_PLAIN.exists():
        USERS_FILE_PLAIN.unlink()

def load_users_from_encrypted(key: bytes) -> dict:
    if not USERS_FILE_ENC.exists():
        return None
    try:
        raw = USERS_FILE_ENC.read_bytes()
        plain = decrypt_data(raw, key)
        return json.loads(plain)
    except Exception:
        return None

def load_users():
    global users_cache
    if users_cache is not None:
        return users_cache
    if admin_key and USERS_FILE_ENC.exists():
        users_cache = load_users_from_encrypted(admin_key)
    return users_cache

# ---------- File operations ----------
def encrypt_file(file_path: Path, fek: bytes):
    enc_path = file_path.with_suffix(file_path.suffix + ".enc")
    aesgcm = AESGCM(fek)
    nonce = secrets.token_bytes(12)
    plaintext = file_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    enc_path.write_bytes(nonce + ciphertext)
    file_path.unlink()            # always delete original
    return enc_path

def decrypt_file(enc_file: Path, fek: bytes):
    if enc_file.suffix != ".enc":
        raise ValueError(f"Not an .enc file: {enc_file}")
    orig_name = enc_file.with_suffix("")
    data = enc_file.read_bytes()
    if len(data) < 12:
        raise ValueError("Encrypted file too short")
    nonce, ciphertext = data[:12], data[12:]
    plaintext = AESGCM(fek).decrypt(nonce, ciphertext, None)
    orig_name.write_bytes(plaintext)
    enc_file.unlink()             # always delete .enc after decryption

# ---------- Auth decorators ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        if not token or token not in session_keys:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        if not token or token not in session_keys:
            return jsonify({"error": "Unauthorized"}), 401
        if not is_admin(session["username"]):
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated

def is_admin(username: str):
    users = load_users()
    return users and username in users and users[username].get("role") == "admin"

# ---------- Routes (same as before, but with wrapping functions now) ----------
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/register", methods=["POST"])
def register():
    global users_cache, admin_key

    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if users_cache is None:
        if USERS_FILE_ENC.exists() or USERS_FILE_PLAIN.exists():
            if admin_key:
                users_cache = load_users_from_encrypted(admin_key)
            if users_cache is None:
                return jsonify({"error": "User database corrupted. Delete users files and restart."}), 500
        else:
            users_cache = {}

    if username in users_cache:
        return jsonify({"error": "Username already exists"}), 409

    role = "admin" if len(users_cache) == 0 else "user"

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    kdf_salt = secrets.token_bytes(16)

    users_cache[username] = {
        "password_hash": hashed,
        "kdf_salt": kdf_salt.hex(),
        "role": role,
        "password": password
    }

    if role == "admin" and admin_key is None:
        derived = derive_key(password, kdf_salt)
        save_admin_key(derived)
        admin_key = derived

    if admin_key:
        save_users_encrypted(users_cache, admin_key)
    else:
        USERS_FILE_PLAIN.write_text(json.dumps(users_cache, indent=2))

    return jsonify({"message": f"User '{username}' registered as {role}"}), 201

@app.route("/login", methods=["POST"])
def login():
    global users_cache

    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if users_cache is None:
        if admin_key and USERS_FILE_ENC.exists():
            users_cache = load_users_from_encrypted(admin_key)
        if users_cache is None:
            return jsonify({"error": "No user database. Register first."}), 400

    if username not in users_cache:
        return jsonify({"error": "Invalid credentials"}), 401

    user_data = users_cache[username]
    if not bcrypt.checkpw(password.encode(), user_data["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    enc_key = derive_key(password, bytes.fromhex(user_data["kdf_salt"]))
    token = secrets.token_hex(32)
    session["token"] = token
    session["username"] = username
    session_keys[token] = enc_key

    return jsonify({
        "message": "Login successful",
        "role": user_data.get("role", "user"),
        "folder": str(vault_folder) if vault_folder else None
    })

@app.route("/logout", methods=["POST"])
def logout():
    token = session.pop("token", None)
    if token and token in session_keys:
        session_keys[token] = b'\x00' * 32
        del session_keys[token]
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/whoami")
@login_required
def whoami():
    users = load_users()
    user_data = users.get(session["username"], {})
    return jsonify({
        "username": session["username"],
        "role": user_data.get("role", "user"),
        "folder": str(vault_folder) if vault_folder else None
    })

# ------------------------------------------------------------
# Encryption – full version with FEK wrapping functions
# ------------------------------------------------------------
@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt_folder():
    data = request.get_json()
    folder = data.get("folder", "").strip()

    if not folder or not os.path.isdir(folder):
        return jsonify({"error": "Invalid folder path"}), 400

    folder_path = Path(folder)
    meta_path = folder_path / ".crypt_meta"
    username = session["username"]
    user_key = session_keys[session["token"]]

    # Load or create metadata
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            return jsonify({"error": "Metadata corrupted"}), 500
    else:
        meta = {"owner": username, "files": {}}

    encrypted_count = 0
    errors = []

    for root, dirs, files in os.walk(folder):
        for name in files:
            file_path = Path(root) / name
            if file_path.name == ".crypt_meta" or file_path.suffix == ".enc":
                continue

            plain_rel = str(file_path.relative_to(folder_path))
            enc_rel = plain_rel + ".enc"

            # ---- Case 1: Metadata exists for this file ----
            if enc_rel in meta["files"]:
                enc_file = folder_path / enc_rel
                if enc_file.exists():
                    continue   # already encrypted, nothing to do

                # .enc is missing → re-encrypt using the original FEK
                # Must have an access entry for the current user
                file_info = meta["files"][enc_rel]
                access_entry = next(
                    (e for e in file_info["access_entries"] if e["user"] == username),
                    None
                )
                if not access_entry:
                    # User has no access to this FEK, skip (or error)
                    errors.append(f"{plain_rel}: you don't have access to re-encrypt this file")
                    continue

                try:
                    fek = unwrap_fek(access_entry["wrapped_fek"], user_key)
                    # Re-encrypt using the exact same FEK
                    enc_path = encrypt_file_with_fek(file_path, fek, enc_file)
                    # No metadata change needed – access entries stay the same
                    encrypted_count += 1
                    fek = b'\x00' * 32
                except Exception as e:
                    errors.append(f"{plain_rel}: {str(e)}")

            # ---- Case 2: No metadata entry → new file ----
            else:
                try:
                    fek = AESGCM.generate_key(bit_length=256)
                    enc_path = encrypt_file(file_path, fek)   # deletes original, creates .enc
                    wrapped_owner = wrap_fek(fek, user_key)
                    meta["files"][enc_rel] = {
                        "access_entries": [{"user": username, "wrapped_fek": wrapped_owner}]
                    }
                    encrypted_count += 1
                    fek = b'\x00' * 32
                except Exception as e:
                    errors.append(f"{plain_rel}: {str(e)}")

    if errors:
        return jsonify({"error": "Encryption failed on some files", "details": errors}), 500

    meta_path.write_text(json.dumps(meta, indent=2))
    return jsonify({"message": f"Encrypted {encrypted_count} new files"})

def encrypt_file_with_fek(file_path: Path, fek: bytes, enc_path: Path) -> Path:
    """Encrypt a plaintext file using a given FEK, write .enc, delete original."""
    aesgcm = AESGCM(fek)
    nonce = secrets.token_bytes(12)
    plaintext = file_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    enc_path.write_bytes(nonce + ciphertext)
    file_path.unlink()
    return enc_path

# ------------------------------------------------------------
# Decryption
# ------------------------------------------------------------
@app.route("/decrypt", methods=["POST"])
@login_required
def decrypt_folder():
    data = request.get_json()
    folder = data.get("folder", "").strip()

    if not folder or not os.path.isdir(folder):
        return jsonify({"error": "Invalid folder path"}), 400

    meta_path = Path(folder) / ".crypt_meta"
    if not meta_path.exists():
        return jsonify({"error": "Folder is not encrypted (no .crypt_meta)"}), 400

    try:
        meta = json.loads(meta_path.read_text())
    except:
        return jsonify({"error": "Metadata corrupted"}), 500

    username = session["username"]
    user_key = session_keys[session["token"]]

    files_meta = meta.get("files", {})
    decrypted_count = 0
    skipped_count = 0
    errors = []

    for enc_rel_path, file_info in files_meta.items():
        enc_file = Path(folder) / enc_rel_path
        if not enc_file.exists():
            continue

        access_entry = next((e for e in file_info["access_entries"] if e["user"] == username), None)
        if not access_entry:
            skipped_count += 1
            continue

        try:
            fek = unwrap_fek(access_entry["wrapped_fek"], user_key)   # <-- now defined
            decrypt_file(enc_file, fek)
            decrypted_count += 1
            fek = b'\x00' * 32
        except Exception as e:
            errors.append(f"{enc_rel_path}: {str(e)}")

    remaining_enc = list(Path(folder).rglob("*.enc"))
    if not remaining_enc:
        meta_path.unlink()

    if errors:
        return jsonify({"error": "Decryption failed on some files", "details": errors}), 500

    return jsonify({
        "message": f"Decrypted {decrypted_count} files, skipped {skipped_count} (no access)."
    })

# ------------------------------------------------------------
# Admin endpoints (unchanged)
# ------------------------------------------------------------
@app.route("/admin/users_full", methods=["GET"])
@admin_required
def users_full():
    users = load_users()
    if users is None:
        return jsonify({"error": "User database not loaded"}), 500
    return jsonify(users)

@app.route("/admin/list_files", methods=["POST"])
@admin_required
def list_files():
    data = request.get_json()
    folder = data.get("folder", "").strip()
    if not folder or not os.path.isdir(folder):
        return jsonify({"files": []})
    meta_path = Path(folder) / ".crypt_meta"
    if not meta_path.exists():
        return jsonify({"files": []})
    try:
        meta = json.loads(meta_path.read_text())
    except:
        return jsonify({"error": "Metadata corrupted"}), 500
    return jsonify({"files": list(meta.get("files", {}).keys())})

@app.route("/admin/grant_file_access", methods=["POST"])
@admin_required
def grant_file_access():
    data = request.get_json()
    folder = data.get("folder", "").strip()
    target_file = data.get("file", "").strip()
    target_user = data.get("username", "").strip()

    if not all([folder, target_file, target_user]):
        return jsonify({"error": "Missing parameters"}), 400

    meta_path = Path(folder) / ".crypt_meta"
    if not meta_path.exists():
        return jsonify({"error": "Folder is not encrypted"}), 400

    try:
        meta = json.loads(meta_path.read_text())
    except:
        return jsonify({"error": "Metadata corrupted"}), 500

    if target_file not in meta["files"]:
        return jsonify({"error": "File not found"}), 404

    file_info = meta["files"][target_file]
    if any(e["user"] == target_user for e in file_info["access_entries"]):
        return jsonify({"message": "User already has access"}), 200

    admin_entry = next((e for e in file_info["access_entries"] if e["user"] == session["username"]), None)
    if not admin_entry:
        return jsonify({"error": "You do not have access to this file"}), 403

    fek = unwrap_fek(admin_entry["wrapped_fek"], session_keys[session["token"]])

    users = load_users()
    if target_user not in users:
        return jsonify({"error": "User not found"}), 404
    target_password = users[target_user].get("password")
    if not target_password:
        return jsonify({"error": "Target user has no stored password"}), 400

    target_salt = bytes.fromhex(users[target_user]["kdf_salt"])
    target_key = derive_key(target_password, target_salt)
    new_wrapped = wrap_fek(fek, target_key)
    file_info["access_entries"].append({"user": target_user, "wrapped_fek": new_wrapped})

    meta_path.write_text(json.dumps(meta, indent=2))
    fek = b'\x00' * 32
    return jsonify({"message": f"Access granted to {target_user} for file {target_file}"})

@app.route("/admin/revoke_file_access", methods=["POST"])
@admin_required
def revoke_file_access():
    data = request.get_json()
    folder = data.get("folder", "").strip()
    target_file = data.get("file", "").strip()
    target_user = data.get("username", "").strip()

    if not all([folder, target_file, target_user]):
        return jsonify({"error": "Missing parameters"}), 400

    meta_path = Path(folder) / ".crypt_meta"
    if not meta_path.exists():
        return jsonify({"error": "Not an encrypted folder"}), 400

    try:
        meta = json.loads(meta_path.read_text())
    except:
        return jsonify({"error": "Metadata corrupted"}), 500

    if target_file not in meta["files"]:
        return jsonify({"error": "File not found"}), 404

    file_info = meta["files"][target_file]
    if target_user == meta.get("owner"):
        return jsonify({"error": "Cannot revoke the folder owner's access"}), 400

    original_len = len(file_info["access_entries"])
    file_info["access_entries"] = [e for e in file_info["access_entries"] if e["user"] != target_user]

    if len(file_info["access_entries"]) == original_len:
        return jsonify({"error": "User did not have access"}), 404

    meta_path.write_text(json.dumps(meta, indent=2))
    return jsonify({"message": f"Access revoked for {target_user} on {target_file}"})

@app.route("/admin/promote", methods=["POST"])
@admin_required
def promote_user():
    data = request.get_json()
    target_user = data.get("username", "").strip()
    if not target_user:
        return jsonify({"error": "Username required"}), 400
    users = load_users()
    if target_user not in users:
        return jsonify({"error": "User not found"}), 404
    users[target_user]["role"] = "admin"
    if admin_key:
        save_users_encrypted(users, admin_key)
    return jsonify({"message": f"{target_user} is now an admin"})

@app.route("/admin/set_vault", methods=["POST"])
@admin_required
def set_vault():
    data = request.get_json()
    folder = data.get("folder", "").strip()
    if not folder or not os.path.isdir(folder):
        return jsonify({"error": "Invalid folder path"}), 400
    path = Path(folder)
    save_vault_folder(path)
    return jsonify({"message": f"Vault folder set to {path}"})

# ---------- Startup ----------
if __name__ == "__main__":
    load_admin_key()
    load_vault_folder()
    if admin_key:
        users_cache = load_users_from_encrypted(admin_key)
        if users_cache is None:
            print("Warning: Could not decrypt user database. Possibly wrong admin_key or corrupted file.")
    else:
        print("No admin key found – first admin registration will create one.")

    # Start Flask in a daemon thread so it doesn't block
    def run_flask():
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.private_mode = False
    flask_thread.start()

    # Give Flask a moment to start up (adjust if needed)
    time.sleep(1)

    # Open the app in a pywebview window
    webview.create_window("Folder Locker Ver. 0.07", "http://127.0.0.1:5000", width=800, height=600)
    webview.start()  # This blocks until the window is closed

    # Optional: clean shutdown (Flask thread will exit because it's a daemon)