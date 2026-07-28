import os
import json
import secrets
import hmac
import hashlib
import re
from pathlib import Path
from functools import wraps
from threading import RLock, Thread
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
import time
import logging
import webview

from flask import Flask, request, jsonify, session, send_from_directory  # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives import hashes  # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[reportMissingImports]
import bcrypt  # type: ignore[reportMissingImports]

# ---------- Configuration ----------
# Use absolute path in user's home directory to avoid permission issues
HOME_DIR = Path.home()
ADMIN_KEY_FILE = HOME_DIR / ".secure_folder_admin_key.bin"
VAULT_FOLDER_FILE = HOME_DIR / ".secure_folder_vault.txt"
USERS_FILE_ENC = HOME_DIR / ".secure_folder_users.json.enc"
ADMIN_RECOVERY_KEY_FILE = HOME_DIR / ".secure_folder_admin_recovery.bin"

SESSION_TIMEOUT = timedelta(hours=2)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
PBKDF2_ITERATIONS = 100_000
BCRYPT_ROUNDS = 12

# Security Questions Pool
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What city were you born in?",
    "What is your mother's maiden name?",
    "What was the name of your elementary school?",
    "What is your favorite book?",
    "What was your childhood nickname?",
    "What is the name of your favorite teacher?",
    "What street did you grow up on?",
    "What is your favorite movie?",
    "What was the make of your first car?"
]

# Fixed encryption key for security questions (used only for forgot password recovery)
# Must be 32 bytes (256 bits) for AES-GCM
SECURITY_QUESTIONS_KEY = b"SecureQKey32BytesLongExactlyNow!"

# ---------- Logging setup ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------- Thread-safe caches ----------
_cache_lock = RLock()
_session_keys: Dict[str, Dict[str, Any]] = {}
_users_cache: Optional[Dict[str, Any]] = None
_admin_key: Optional[bytes] = None
_vault_folder: Optional[Path] = None
_login_attempts: Dict[str, list] = {}

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def load_vault_folder():
    global _vault_folder
    if VAULT_FOLDER_FILE.exists():
        _vault_folder = Path(VAULT_FOLDER_FILE.read_text().strip())
    else:
        _vault_folder = None

def save_vault_folder(path: Path):
    VAULT_FOLDER_FILE.write_text(str(path))
    global _vault_folder
    _vault_folder = path

# ---------- Admin key persistence ----------
def load_admin_key():
    global _admin_key
    if ADMIN_KEY_FILE.exists():
        _admin_key = ADMIN_KEY_FILE.read_bytes()
        return True
    return False

def save_admin_key(key: bytes):
    ADMIN_KEY_FILE.write_bytes(key)
    global _admin_key
    _admin_key = key

def save_admin_recovery_key(recovery_key: bytes):
    """Save admin recovery key for emergency file re-encryption."""
    ADMIN_RECOVERY_KEY_FILE.write_bytes(encrypt_data(recovery_key, _admin_key))

def load_admin_recovery_key() -> Optional[bytes]:
    """Load admin recovery key encrypted with admin key."""
    if not ADMIN_RECOVERY_KEY_FILE.exists() or not _admin_key:
        return None
    try:
        encrypted = ADMIN_RECOVERY_KEY_FILE.read_bytes()
        return decrypt_data(encrypted, _admin_key)
    except Exception:
        return None

def generate_recovery_key() -> bytes:
    """Generate a random recovery key for admin use."""
    return secrets.token_bytes(32)

# ---------- Crypto helpers ----------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-GCM with random nonce."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_data(payload: bytes, key: bytes) -> bytes:
    """Decrypt AES-GCM encrypted data."""
    if len(payload) < 12:
        raise ValueError("Payload too short")
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ---------- FEK wrapping ----------
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

def load_users_from_encrypted(key: bytes) -> Optional[dict]:
    if not USERS_FILE_ENC.exists():
        return None
    try:
        raw = USERS_FILE_ENC.read_bytes()
        plain = decrypt_data(raw, key)
        return json.loads(plain)
    except Exception:
        return None

def load_users() -> Optional[dict]:
    global _users_cache
    with _cache_lock:
        if _users_cache is not None:
            return _users_cache
        if _admin_key and USERS_FILE_ENC.exists():
            _users_cache = load_users_from_encrypted(_admin_key)
        return _users_cache

def invalidate_users_cache():
    global _users_cache
    with _cache_lock:
        _users_cache = None

# ---------- File operations ----------
def encrypt_file(file_path: Path, fek: bytes) -> Path:
    """Encrypt a file with given FEK, write .enc, delete original."""
    enc_path = file_path.with_suffix(file_path.suffix + ".enc")
    aesgcm = AESGCM(fek)
    nonce = secrets.token_bytes(12)
    plaintext = file_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    enc_path.write_bytes(nonce + ciphertext)
    file_path.unlink(missing_ok=True)
    return enc_path

def decrypt_file(enc_file: Path, fek: bytes) -> Path:
    """Decrypt a .enc file, write original, delete .enc."""
    if enc_file.suffix != ".enc":
        raise ValueError(f"Not an .enc file: {enc_file}")
    orig_name = enc_file.with_suffix("")
    data = enc_file.read_bytes()
    if len(data) < 12:
        raise ValueError("Encrypted file too short")
    nonce, ciphertext = data[:12], data[12:]
    plaintext = AESGCM(fek).decrypt(nonce, ciphertext, None)
    orig_name.write_bytes(plaintext)
    enc_file.unlink(missing_ok=True)
    return orig_name

# ---------- Auth decorators ----------
def _validate_session(token: str) -> bool:
    """Validate session token and check for expiration."""
    if not token or token not in _session_keys:
        return False
    session_data = _session_keys[token]
    # Check session timeout
    if "created_at" in session_data:
        created = datetime.fromisoformat(session_data["created_at"])
        if datetime.now() - created > SESSION_TIMEOUT:
            # Session expired
            del _session_keys[token]
            return False
    return True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        if not _validate_session(token):
            session.clear()
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        if not _validate_session(token):
            session.clear()
            return jsonify({"error": "Unauthorized"}), 401
        username = session.get("username")
        if not username or not is_admin(username):
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated

def is_admin(username: str) -> bool:
    users = load_users()
    return users is not None and username in users and users[username].get("role") == "admin"

# ---------- Rate limiting helper ----------
def _check_rate_limit(username: str) -> tuple[bool, Optional[str]]:
    """Check if user is rate-limited. Returns (allowed, error_message)."""
    now = datetime.now()
    if username in _login_attempts:
        attempts = _login_attempts[username]
        # Filter out old attempts
        recent = [t for t in attempts if now - t < LOCKOUT_DURATION]
        if len(recent) >= MAX_LOGIN_ATTEMPTS:
            # Check if locked out
            last_attempt = max(recent)
            if now - last_attempt < LOCKOUT_DURATION:
                return False, "Too many failed attempts. Please try again later."
        _login_attempts[username] = recent
    return True, None

def _record_login_attempt(username: str, success: bool):
    """Record a login attempt."""
    now = datetime.now()
    if username not in _login_attempts:
        _login_attempts[username] = []
    if success:
        _login_attempts[username] = []  # Reset on success
    else:
        _login_attempts[username].append(now)

# ---------- Routes ----------
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/register", methods=["POST"])
def register():
    """Register a new user. First user becomes admin."""
    global _users_cache, _admin_key

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
    except Exception as e:
        logger.error(f"Invalid JSON in registration: {e}")
        return jsonify({"error": "Invalid request format"}), 400

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    security_questions = data.get("security_questions", [])  # List of {question, answer}

    # Validate input
    if not username:
        return jsonify({"error": "Username is required"}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be between 3 and 32 characters"}), 400
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username can only contain letters, numbers, and underscores"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(password) > 128:
        return jsonify({"error": "Password is too long (max 128 characters)"}), 400
    
    # Validate security questions (require at least 2)
    if not security_questions or len(security_questions) < 2:
        return jsonify({"error": "At least 2 security questions are required"}), 400
    if len(security_questions) > 3:
        return jsonify({"error": "Maximum 3 security questions allowed"}), 400
    
    for sq in security_questions:
        if not sq.get("question") or not sq.get("answer"):
            return jsonify({"error": "Each security question must have a question and answer"}), 400
        if len(sq["answer"]) < 2:
            return jsonify({"error": "Security question answers must be at least 2 characters"}), 400

    with _cache_lock:
        # Initialize users cache if needed
        if _users_cache is None:
            if USERS_FILE_ENC.exists():
                if _admin_key:
                    _users_cache = load_users_from_encrypted(_admin_key)
                if _users_cache is None:
                    logger.error("User database corrupted")
                    return jsonify({"error": "User database corrupted. Please contact administrator."}), 500
            else:
                _users_cache = {}

        # Check if username already exists
        if username in _users_cache:
            return jsonify({"error": "Username already exists"}), 409

        # Determine role (first user is admin)
        role = "admin" if len(_users_cache) == 0 else "user"

        # Hash password with bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
        kdf_salt = secrets.token_bytes(16)
        
        # Derive user's encryption key from password
        user_enc_key = derive_key(password, kdf_salt)

        # Store user data - encrypt user's encryption key with admin key for later access granting
        user_key_wrapped = None
        if _admin_key:
            # Wrap the user's encryption key with admin key so admin can grant access later
            user_key_wrapped = wrap_fek(user_enc_key, _admin_key)
        else:
            # First admin - will be set after this block, store key temporarily
            # It will be wrapped when the next user registers
            pass

        # Encrypt security question answers with fixed key for forgot password recovery
        security_data = []
        for sq in security_questions:
            # Normalize answer: lowercase and strip whitespace
            normalized_answer = sq["answer"].strip().lower()
            # Encrypt the answer with fixed key
            encrypted_answer = encrypt_data(normalized_answer.encode(), SECURITY_QUESTIONS_KEY)
            security_data.append({
                "question": sq["question"],
                "encrypted_answer": encrypted_answer.hex()  # Store as hex string
            })

        _users_cache[username] = {
            "password_hash": hashed,
            "kdf_salt": kdf_salt.hex(),
            "role": role,
            "created_at": datetime.now().isoformat(),
            "user_key_wrapped": user_key_wrapped,  # Encrypted user key for admin access granting
            "security_questions": security_data  # Hashed security questions
        }

        # If first admin, derive and save admin key
        if role == "admin" and _admin_key is None:
            derived = derive_key(password, kdf_salt)
            try:
                save_admin_key(derived)
                _admin_key = derived
                # Now wrap the first admin's key with the newly created admin key
                _users_cache[username]["user_key_wrapped"] = wrap_fek(user_enc_key, derived)
                # Generate and save admin recovery key
                recovery_key = generate_recovery_key()
                save_admin_recovery_key(recovery_key)
                # Re-save users with the wrapped key
                save_users_encrypted(_users_cache, _admin_key)
            except PermissionError as e:
                logger.error(f"Permission denied saving admin key: {e}")
                del _users_cache[username]
                return jsonify({"error": "Failed to save admin key. Check file permissions."}), 500

        # Save encrypted user database
        if _admin_key:
            try:
                save_users_encrypted(_users_cache, _admin_key)
            except Exception as e:
                logger.error(f"Failed to save user database: {e}")
                del _users_cache[username]
                return jsonify({"error": "Failed to save user data"}), 500

    logger.info(f"New user registered: {username} ({role})")
    return jsonify({
        "message": f"User '{username}' registered successfully as {role}",
        "role": role,
        "security_questions_count": len(security_data)
    }), 201

@app.route("/login", methods=["POST"])
def login():
    """Authenticate user and create session."""
    global _users_cache

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
    except Exception as e:
        logger.error(f"Invalid JSON in login: {e}")
        return jsonify({"error": "Invalid request format"}), 400

    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    # Basic input validation
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Rate limiting check
    allowed, error_msg = _check_rate_limit(username)
    if not allowed:
        logger.warning(f"Rate limited login attempt for: {username}")
        return jsonify({"error": error_msg}), 429

    with _cache_lock:
        # Initialize users cache if needed
        if _users_cache is None:
            if _admin_key and USERS_FILE_ENC.exists():
                _users_cache = load_users_from_encrypted(_admin_key)
            if _users_cache is None:
                return jsonify({"error": "No user database. Please register first."}), 400

        # Check if user exists
        if username not in _users_cache:
            _record_login_attempt(username, False)
            logger.info(f"Failed login attempt for non-existent user: {username}")
            # Use generic message to prevent user enumeration
            return jsonify({"error": "Invalid credentials"}), 401

        user_data = _users_cache[username]
        
        # Verify password with bcrypt (constant-time comparison)
        try:
            if not bcrypt.checkpw(password.encode(), user_data["password_hash"].encode()):
                _record_login_attempt(username, False)
                logger.info(f"Failed login attempt for user: {username}")
                return jsonify({"error": "Invalid credentials"}), 401
        except Exception as e:
            logger.error(f"Error during password verification: {e}")
            return jsonify({"error": "Authentication error"}), 500

        # Successful login - reset rate limit counter
        _record_login_attempt(username, True)

        # Derive encryption key for this user
        try:
            enc_key = derive_key(password, bytes.fromhex(user_data["kdf_salt"]))
        except Exception as e:
            logger.error(f"Error deriving key for user {username}: {e}")
            return jsonify({"error": "Authentication error"}), 500

        # Generate secure session token
        token = secrets.token_hex(32)
        
        session.permanent = True
        session["token"] = token
        session["username"] = username
        
        # Store session metadata including creation time
        _session_keys[token] = {
            "key": enc_key,
            "created_at": datetime.now().isoformat()
        }

    logger.info(f"User logged in: {username}")
    return jsonify({
        "message": "Login successful",
        "role": user_data.get("role", "user"),
        "folder": str(_vault_folder) if _vault_folder else None
    })

@app.route("/logout", methods=["POST"])
def logout():
    token = session.pop("token", None)
    if token and token in _session_keys:
        # Securely clear the key from memory
        _session_keys[token]["key"] = b'\x00' * 32
        del _session_keys[token]
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/whoami")
@login_required
def whoami():
    users = load_users()
    username = session.get("username", "")
    user_data = users.get(username, {}) if users else {}
    return jsonify({
        "username": username,
        "role": user_data.get("role", "user"),
        "folder": str(_vault_folder) if _vault_folder else None
    })

@app.route("/security_questions", methods=["GET"])
def get_security_questions():
    """Return available security questions for registration."""
    return jsonify({"questions": SECURITY_QUESTIONS})

@app.route("/forgot_password/questions", methods=["POST"])
def forgot_password_get_questions():
    """Get user's security questions for password recovery (without revealing answers)."""
    global _users_cache
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
    except Exception as e:
        logger.error(f"Invalid JSON in forgot password get questions: {e}")
        return jsonify({"error": "Invalid request format"}), 400

    username = data.get("username", "").strip().lower()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    with _cache_lock:
        if _users_cache is None:
            if _admin_key and USERS_FILE_ENC.exists():
                _users_cache = load_users_from_encrypted(_admin_key)
            if _users_cache is None:
                return jsonify({"error": "No user database"}), 400

        if username not in _users_cache:
            return jsonify({"error": "User not found", "success": False}), 404

        user_data = _users_cache[username]
        stored_questions = user_data.get("security_questions", [])

        if not stored_questions:
            return jsonify({"error": "No security questions set for this user", "success": False}), 400

        # Return only the question texts (not hashes or salts)
        questions_list = [sq["question"] for sq in stored_questions]
        
        return jsonify({
            "success": True,
            "questions": questions_list
        })

@app.route("/forgot_password/verify", methods=["POST"])
def forgot_password_verify():
    """Verify security question answers for password reset."""
    global _users_cache
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
    except Exception as e:
        logger.error(f"Invalid JSON in forgot password verify: {e}")
        return jsonify({"error": "Invalid request format"}), 400

    username = data.get("username", "").strip().lower()
    answers = data.get("answers", [])  # List of {question, answer}

    if not username or not answers:
        return jsonify({"error": "Username and answers are required"}), 400

    with _cache_lock:
        if _users_cache is None:
            if _admin_key and USERS_FILE_ENC.exists():
                _users_cache = load_users_from_encrypted(_admin_key)
            if _users_cache is None:
                return jsonify({"error": "No user database"}), 400

        if username not in _users_cache:
            return jsonify({"error": "User not found"}), 404

        user_data = _users_cache[username]
        stored_questions = user_data.get("security_questions", [])

        if not stored_questions:
            return jsonify({"error": "No security questions set for this user"}), 400

        # Check if at least 2 answers match (require majority)
        correct_count = 0
        for provided in answers:
            question_text = provided.get("question", "").strip()
            answer_text = provided.get("answer", "").strip().lower()
            
            # Find matching question in stored questions
            for stored in stored_questions:
                if stored["question"] == question_text:
                    # Decrypt the stored answer with fixed key
                    try:
                        encrypted_answer = bytes.fromhex(stored["encrypted_answer"])
                        decrypted_answer = decrypt_data(encrypted_answer, SECURITY_QUESTIONS_KEY).decode()
                        if decrypted_answer == answer_text:
                            correct_count += 1
                    except Exception as e:
                        logger.error(f"Failed to decrypt answer: {e}")
                    break

        # Require at least 2 correct answers (or all if only 2 questions)
        required_correct = min(2, len(stored_questions))
        if correct_count >= required_correct:
            # Generate a temporary reset token
            reset_token = secrets.token_hex(32)
            # Store token with expiration (15 minutes)
            if not hasattr(app, 'reset_tokens'):
                app.reset_tokens = {}
            app.reset_tokens[reset_token] = {
                "username": username,
                "expires": datetime.now() + timedelta(minutes=15)
            }
            logger.info(f"Password reset verified for user: {username}")
            return jsonify({
                "success": True,
                "reset_token": reset_token,
                "message": "Security questions verified. You may now reset your password."
            })
        else:
            logger.warning(f"Failed security question verification for: {username}")
            return jsonify({"error": "Incorrect answers. Please try again."}), 401

@app.route("/forgot_password/reset", methods=["POST"])
def forgot_password_reset():
    """Reset password using valid reset token."""
    global _users_cache, _admin_key
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request format"}), 400
    except Exception as e:
        logger.error(f"Invalid JSON in forgot password reset: {e}")
        return jsonify({"error": "Invalid request format"}), 400

    reset_token = data.get("reset_token", "")
    new_password = data.get("new_password", "")

    if not reset_token or not new_password:
        return jsonify({"error": "Reset token and new password are required"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if len(new_password) > 128:
        return jsonify({"error": "Password is too long (max 128 characters)"}), 400

    # Validate reset token
    if not hasattr(app, 'reset_tokens') or reset_token not in app.reset_tokens:
        return jsonify({"error": "Invalid or expired reset token"}), 400

    token_data = app.reset_tokens[reset_token]
    if datetime.now() > token_data["expires"]:
        del app.reset_tokens[reset_token]
        return jsonify({"error": "Reset token has expired"}), 400

    username = token_data["username"]

    with _cache_lock:
        if _users_cache is None:
            if _admin_key and USERS_FILE_ENC.exists():
                _users_cache = load_users_from_encrypted(_admin_key)
            if _users_cache is None:
                return jsonify({"error": "No user database"}), 400

        if username not in _users_cache:
            return jsonify({"error": "User not found"}), 404

        user_data = _users_cache[username]
        
        # Hash new password
        new_hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
        
        # Derive new encryption key from new password
        new_kdf_salt = secrets.token_bytes(16)
        new_user_enc_key = derive_key(new_password, new_kdf_salt)
        
        # Re-wrap user's encryption key with admin key
        if not _admin_key:
            return jsonify({"error": "Admin key not available"}), 500
        
        new_wrapped_key = wrap_fek(new_user_enc_key, _admin_key)
        
        # Update user data
        _users_cache[username]["password_hash"] = new_hashed
        _users_cache[username]["kdf_salt"] = new_kdf_salt.hex()
        _users_cache[username]["user_key_wrapped"] = new_wrapped_key
        
        # Save updated users database
        try:
            save_users_encrypted(_users_cache, _admin_key)
        except Exception as e:
            logger.error(f"Failed to save user database after password reset: {e}")
            return jsonify({"error": "Failed to save new password"}), 500

        # Invalidate the reset token
        del app.reset_tokens[reset_token]

        # If this is the admin, we need to re-encrypt all files with the new recovery key
        if user_data.get("role") == "admin":
            # Generate new recovery key and save it
            new_recovery_key = generate_recovery_key()
            save_admin_recovery_key(new_recovery_key)
            logger.info(f"Admin recovery key regenerated after password reset")
            
            # Note: Files encrypted with old FEKs wrapped by admin key will need re-wrapping
            # This is handled by the admin on next login or via a dedicated endpoint

    logger.info(f"Password reset successful for user: {username}")
    return jsonify({
        "success": True,
        "message": "Password has been reset successfully. You can now log in with your new password."
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
    token = session.get("token")
    if not token or token not in _session_keys:
        return jsonify({"error": "Unauthorized"}), 401
    user_key = _session_keys[token]["key"]

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
    token = session.get("token")
    if not token or token not in _session_keys:
        return jsonify({"error": "Unauthorized"}), 401
    user_key = _session_keys[token]["key"]

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
    # Return user data without passwords (keys are stored encrypted, not plaintext)
    result = {}
    for username, data in users.items():
        result[username] = {
            "role": data.get("role", "user"),
            "created_at": data.get("created_at", ""),
            "has_key_wrapped": data.get("user_key_wrapped") is not None  # Indicate if key is available for access granting
        }
    return jsonify(result)

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

    token = session.get("token")
    if not token or token not in _session_keys:
        return jsonify({"error": "Unauthorized"}), 401
    user_key = _session_keys[token]["key"]
    fek = unwrap_fek(admin_entry["wrapped_fek"], user_key)

    users = load_users()
    if target_user not in users:
        return jsonify({"error": "User not found"}), 404
    
    # Get target user's wrapped encryption key and unwrap it with admin key
    target_user_data = users[target_user]
    user_key_wrapped = target_user_data.get("user_key_wrapped")
    if not user_key_wrapped:
        return jsonify({"error": "Target user key not available. User may have been created before encrypted key storage was enabled."}), 500
    
    # Unwrap the target user's encryption key using admin's key
    try:
        token = session.get("token")
        if not token or token not in _session_keys:
            return jsonify({"error": "Unauthorized"}), 401
        admin_key = _session_keys[token]["key"]
        target_key = unwrap_fek(user_key_wrapped, admin_key)
    except Exception as e:
        logger.error(f"Error unwrapping key for target user {target_user}: {e}")
        return jsonify({"error": "Failed to retrieve target user key"}), 500

    # Wrap FEK for target user
    wrapped_fek = wrap_fek(fek, target_key)
    
    # Add access entry for target user
    file_info["access_entries"].append({
        "user": target_user,
        "wrapped_fek": wrapped_fek
    })
    
    # Save updated metadata
    meta_path.write_text(json.dumps(meta, indent=2))
    
    logger.info(f"Admin {session['username']} granted access to {target_file} for user {target_user}")
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
    global _users_cache
    data = request.get_json()
    target_user = data.get("username", "").strip().lower()
    if not target_user:
        return jsonify({"error": "Username required"}), 400
    users = load_users()
    if users is None or target_user not in users:
        return jsonify({"error": "User not found"}), 404
    users[target_user]["role"] = "admin"
    if _admin_key:
        save_users_encrypted(users, _admin_key)
        invalidate_users_cache()
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

@app.route("/admin/browse_folder", methods=["POST"])
@admin_required
def browse_folder():
    """Open a folder browser dialog and return the selected folder path."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        
        # Create a hidden Tkinter window for the file dialog
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        root.attributes('-topmost', True)  # Bring dialog to front
        
        # Open directory selection dialog
        selected_folder = filedialog.askdirectory(title="Select Vault Folder")
        
        root.destroy()  # Clean up the Tkinter window
        
        if selected_folder:
            return jsonify({"folder": selected_folder})
        else:
            return jsonify({"error": "No folder selected"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to open folder browser: {str(e)}"}), 500

@app.route("/admin/reset_app", methods=["POST"])
@admin_required
def reset_app():
    """Reset app to initial setup by removing all stored data."""
    global _users_cache, _admin_key, _vault_folder
    
    token = session.get("token")
    if not token or token not in _session_keys:
        return jsonify({"error": "Unauthorized"}), 401
    user_key = _session_keys[token]["key"]
    
    # First, decrypt any encrypted files in the vault folder
    vault_path = _vault_folder
    if vault_path and vault_path.exists():
        try:
            # Find all .enc files and decrypt them
            for enc_file in vault_path.rglob("*.enc"):
                try:
                    # Try to get FEK from metadata
                    parent_folder = enc_file.parent
                    meta_path = parent_folder / ".crypt_meta"
                    if meta_path.exists():
                        meta = json.loads(meta_path.read_text())
                        file_name = enc_file.name[:-4]  # Remove .enc suffix
                        if file_name in meta.get("files", {}):
                            file_info = meta["files"][file_name]
                            # Find admin's access entry
                            admin_entry = next((e for e in file_info["access_entries"] if e["user"] == session["username"]), None)
                            if admin_entry:
                                fek = unwrap_fek(admin_entry["wrapped_fek"], user_key)
                                decrypt_file(enc_file, fek)
                                logger.info(f"Decrypted file during reset: {enc_file}")
                except Exception as e:
                    logger.error(f"Error decrypting file {enc_file} during reset: {e}")
            
            # Remove .crypt_meta files
            for meta_file in vault_path.rglob(".crypt_meta"):
                try:
                    meta_file.unlink()
                    logger.info(f"Removed metadata file: {meta_file}")
                except Exception as e:
                    logger.error(f"Error removing metadata file {meta_file}: {e}")
        except Exception as e:
            logger.error(f"Error during vault decryption in reset: {e}")
    
    # Remove all stored data files
    files_removed = []
    try:
        if ADMIN_KEY_FILE.exists():
            ADMIN_KEY_FILE.unlink()
            files_removed.append(str(ADMIN_KEY_FILE))
            logger.info("Removed admin key file")
    except Exception as e:
        logger.error(f"Error removing admin key file: {e}")
    
    try:
        if ADMIN_RECOVERY_KEY_FILE.exists():
            ADMIN_RECOVERY_KEY_FILE.unlink()
            files_removed.append(str(ADMIN_RECOVERY_KEY_FILE))
            logger.info("Removed admin recovery key file")
    except Exception as e:
        logger.error(f"Error removing admin recovery key file: {e}")
    
    try:
        if VAULT_FOLDER_FILE.exists():
            VAULT_FOLDER_FILE.unlink()
            files_removed.append(str(VAULT_FOLDER_FILE))
            logger.info("Removed vault folder file")
    except Exception as e:
        logger.error(f"Error removing vault folder file: {e}")
    
    try:
        if USERS_FILE_ENC.exists():
            USERS_FILE_ENC.unlink()
            files_removed.append(str(USERS_FILE_ENC))
            logger.info("Removed users database file")
    except Exception as e:
        logger.error(f"Error removing users database file: {e}")
    
    # Clear in-memory caches
    _users_cache = None
    _admin_key = None
    _vault_folder = None
    
    # Clear session
    session.clear()
    
    logger.info(f"App reset completed by user {session.get('username', 'unknown')}. Files removed: {files_removed}")
    
    return jsonify({
        "message": "App has been reset to initial setup. All users, passwords, and vault data have been removed.",
        "files_removed": files_removed
    })

# ---------- Startup ----------
if __name__ == "__main__":
    load_admin_key()
    load_vault_folder()
    if _admin_key:
        _users_cache = load_users_from_encrypted(_admin_key)
        if _users_cache is None:
            print("Warning: Could not decrypt user database. Possibly wrong admin_key or corrupted file.")
    else:
        print("No admin key found – first admin registration will create one.")

    # Start Flask in a daemon thread so it doesn't block
    def run_flask():
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Give Flask a moment to start up (adjust if needed)
    time.sleep(1)

    # Open the app in a pywebview window
    webview.create_window("Folder Locker Ver. 0.07", "http://127.0.0.1:5000", width=800, height=600)
    webview.start()  # This blocks until the window is closed

    # Optional: clean shutdown (Flask thread will exit because it's a daemon)