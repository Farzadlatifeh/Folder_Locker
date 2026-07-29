# 🔐 Secure Folder v.1

A secure file encryption application with multi-user support, role-based access control, and enterprise-grade security features. Built with Flask (backend) and vanilla JavaScript (frontend), using AES-GCM-256 encryption for file protection. Packaged as a desktop application using pywebview.

## 📋 Features

### Core Capabilities
- **File Encryption/Decryption**: Encrypt folders with AES-GCM-256 encryption using per-file keys
- **Multi-User System**: Support for multiple users with individual accounts and passwords
- **Role-Based Access Control (RBAC)**: Admin and regular user roles with distinct privileges
- **Fine-Grained File Access Control**: Admins can grant/revoke file access per user via access entries
- **Password Recovery**: Security question-based account recovery system with automatic key re-wrapping
- **Desktop Application**: Native window interface using pywebview

### Security Features
- **AES-GCM-256 Encryption**: Industry-standard authenticated encryption with random nonces
- **PBKDF2-HMAC-SHA256**: Key derivation with 100,000 iterations for password-to-key conversion
- **bcrypt Password Hashing**: 12 rounds for secure password storage with salt
- **Session Management**: HTTPOnly, SameSite cookies with 2-hour timeout
- **Rate Limiting**: Account lockout after 5 failed login attempts (15-minute lockout)
- **Input Validation**: Comprehensive server-side validation (username: 3-32 alphanumeric+underscore, password: 8-128 chars)
- **User Enumeration Prevention**: Generic error messages for login failures
- **Secure Key Storage**: Admin key and user database encrypted at rest in home directory
- **Thread-Safe Caching**: RLock-protected caches for sessions and user data
- **Path Traversal Protection**: Server-side validation of folder paths

### User Experience
- **Modern UI**: Dark theme with responsive design in index.html
- **Real-time Feedback**: Toast notifications with color-coded success/error/info messages
- **Client-Side Validation**: Immediate input validation before server requests
- **Native Folder Browser**: pywebview-powered folder selection dialog
- **Search Functionality**: Filter users and files quickly
- **Auto-Clear Messages**: Success messages auto-clear after 3 seconds

## 🏗️ Architecture

```
┌─────────────────┐      ┌──────────────────┐     ┌─────────────────┐
│   index.html    │────▶│  secure_folder   │────▶│  File System    │
│   (Frontend)    │      │     v.1.py       │     │  (Encrypted)    │
│                 │◀────│   (Flask App)    │◀────│                 │
└─────────────────┘      └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Home Directory  │
                        │  - .secure_folder_admin_key.bin
                        │  - .secure_folder_users.json.enc
                        │  - .secure_folder_vault.txt
                        │  - .secure_folder_admin_recovery.bin
                        └──────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  pywebview       │
                        │  (Desktop Window)│
                        └──────────────────┘
```

### Application Flow
1. **Startup**: `secure_folder_v.1.py` launches Flask server on `http://127.0.0.1:5000` and opens pywebview window
2. **First Run**: First user to register becomes admin automatically
3. **Vault Setup**: Admin configures shared vault folder for encrypted file storage
4. **Encryption**: Files encrypted with per-file FEK (File Encryption Key), FEK wrapped with user keys
5. **Access Control**: Admin grants file access by wrapping FEK with additional user keys
6. **Password Recovery**: Security questions verify identity, password reset re-wraps all FEKs

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Modern web browser (if not using pywebview desktop mode)

### Dependencies

Install required packages:

```bash
pip install flask cryptography bcrypt pywebview
```

Or create a virtual environment first (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install flask cryptography bcrypt pywebview
```

### Required Packages
- `flask` (v2.0+) - Lightweight web framework for API endpoints
- `cryptography` (v35.0+) - AES-GCM encryption, PBKDF2 key derivation
- `bcrypt` (v3.2+) - Password hashing with salt
- `pywebview` (v4.0+) - Native desktop window wrapper

### File Structure
```
/workspace/
├── secure_folder_v.1.py   # Main application (Flask backend + pywebview)
├── index.html             # Frontend UI (served by Flask)
├── favicon.ico            # Application icon
├── README.md              # This documentation
└── IMPROVEMENTS.md        # Development notes and security recommendations
```

## 🚀 Quick Start

### First Run (Admin Setup)

1. **Start the application:**
   ```bash
   python secure_folder_v.1.py
   ```
   
   This will:
   - Start Flask server on `http://127.0.0.1:5000`
   - Open a native desktop window using pywebview
   - Display the login/registration interface

2. **Register as Admin:**
   - The first user to register automatically becomes an administrator
   - Choose a strong password (minimum 8 characters, max 128)
   - Username must be 3-32 characters (alphanumeric and underscore only)
   - Select 2-3 security questions for account recovery
   - Save your answers carefully (case-insensitive, trimmed)

3. **Set Vault Folder:**
   - As admin, navigate to Admin Panel
   - Click "Browse" to select vault folder location using native dialog
   - Or enter path manually and click "Set Vault"
   - This folder will store all encrypted files (.enc) and metadata (.crypt_meta)

### Regular Usage

#### For Users:
1. **Login** with your credentials (subject to rate limiting: 5 attempts max)
2. **Enter folder path** you want to encrypt/decrypt
3. **Click Encrypt** to secure your files:
   - Original files deleted
   - `.enc` files created with AES-GCM encryption
   - `.crypt_meta` file stores access control metadata
4. **Click Decrypt** to access encrypted files:
   - Requires valid access entry in metadata
   - `.enc` files decrypted back to original
   - Encrypted files deleted after successful decryption

#### For Admins:
In addition to user capabilities, admins can:
- **Manage Users**: View all registered users with roles and security questions
- **Grant File Access**: Allow specific users to access specific encrypted files
- **Revoke File Access**: Remove user access to files immediately
- **Promote Users**: Elevate trusted users to admin role
- **Configure Vault**: Set/change the shared vault folder location
- **Reset App**: Complete factory reset (decrypts all files, removes all data)

## 📖 API Reference

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register new user (first user becomes admin) |
| `/login` | POST | Authenticate user and create session |
| `/logout` | POST | End user session |
| `/whoami` | GET | Get current user information |
| `/security_questions` | GET | Get available security questions |

### Password Recovery Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/forgot_password/questions` | POST | Get user's security questions |
| `/forgot_password/verify` | POST | Verify security question answers |
| `/forgot_password/reset` | POST | Reset password with valid token |

### File Operations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/encrypt` | POST | Encrypt a folder |
| `/decrypt` | POST | Decrypt a folder |

### Admin Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/users_full` | GET | List all users with details |
| `/admin/list_files` | POST | List encrypted files in vault |
| `/admin/grant_file_access` | POST | Grant user access to file |
| `/admin/revoke_file_access` | POST | Revoke user access to file |
| `/admin/promote` | POST | Promote user to admin |
| `/admin/set_vault` | POST | Set vault folder location |
| `/admin/browse_folder` | POST | Open native folder browser |
| `/admin/reset_app` | POST | Reset application to initial state |

## 🔐 Security Model

### Encryption Flow

1. **File Encryption Key (FEK)**: Random 256-bit key generated per file/folder using `secrets.token_bytes(32)`
2. **Key Derivation**: User password → PBKDF2-HMAC-SHA256 (100K iterations) → 32-byte user key
3. **Key Wrapping**: FEK encrypted with user key using AES-GCM-256, stored in access entry
4. **Access Control**: Multiple wrapped FEKs stored in `.crypt_meta` for authorized users
5. **Admin Override**: Admin can access any file via recovery key or by wrapping with admin key
6. **Password Reset**: Re-wraps all FEKs with new user key (preserves file access)

### Key Hierarchy

```
Admin Key (derived from admin password via PBKDF2)
    ├── Recovery Key (AES-GCM encrypted backup)
    └── User Database (AES-GCM encrypted JSON)

User Key (derived from user password via PBKDF2)
    └── Wrapped FEKs (AES-GCM, stored in .crypt_meta files)

File Encryption Key (FEK - random 256-bit per file)
    └── Encrypts actual file content (AES-GCM-256)
```

### Data Storage

All sensitive data stored encrypted in user's home directory (`~`):

| File | Purpose | Encryption |
|------|---------|------------|
| `~/.secure_folder_admin_key.bin` | Admin master key (raw bytes) | None (generated from password) |
| `~/.secure_folder_users.json.enc` | User database (JSON) | AES-GCM with admin key |
| `~/.secure_folder_vault.txt` | Vault folder path (plaintext) | None |
| `~/.secure_folder_admin_recovery.bin` | Recovery key backup | AES-GCM with admin key |
| `<vault>/**/*.enc` | Encrypted files | AES-GCM with FEK |
| `<vault>/**/.crypt_meta` | Access metadata (JSON) | Plaintext structure, wrapped keys |

### Cryptographic Parameters

| Algorithm | Purpose | Parameters |
|-----------|---------|------------|
| PBKDF2-HMAC-SHA256 | Password → Key | 100,000 iterations, 32-byte output |
| bcrypt | Password hashing | 12 rounds, random salt |
| AES-GCM-256 | File encryption | 12-byte random nonce, 256-bit key |
| AES-GCM-256 | Key wrapping | 12-byte random nonce, 256-bit key |

### Session Security

- **Token Generation**: `secrets.token_urlsafe(32)` for session tokens
- **Cookie Flags**: `HttpOnly=True`, `SameSite='Lax'`
- **Timeout**: 2 hours of inactivity
- **Storage**: In-memory dictionary (`_session_keys`) with RLock protection
- **Cleanup**: Keys zeroed on logout

### Rate Limiting

- **Threshold**: 5 failed login attempts per username
- **Lockout**: 15 minutes before reset
- **Tracking**: In-memory dictionary (`_login_attempts`)
- **Scope**: Per-username, not per-IP

## 👥 User Roles

### Admin Privileges
- ✅ Grant/revoke file access for any user
- ✅ Promote users to admin role
- ✅ Configure vault folder location
- ✅ View complete user list
- ✅ Reset application
- ✅ Access all encrypted files

### Regular User Privileges
- ✅ Encrypt/decrypt own folders
- ✅ Access files with granted permissions
- ✅ Update own password (via recovery)
- ❌ Cannot manage other users
- ❌ Cannot modify vault settings

## 🔒 Password Recovery

The application includes a comprehensive self-service password recovery system:

### Registration Phase
1. **Security Questions Selection**: Users select 2-3 questions from pool of 10 during registration
2. **Answer Storage**: Answers stored encrypted in user database (case-insensitive, trimmed)
3. **Question Pool**: 
   - First pet name, Birth city, Mother's maiden name
   - Elementary school, Favorite book, Childhood nickname
   - Favorite teacher, Street grew up on, Favorite movie, First car make

### Recovery Process
1. Click "Forgot Password?" on login screen
2. Enter username → System retrieves encrypted security questions
3. Answer all security questions → Case-insensitive comparison
4. System issues temporary reset token (valid for single use)
5. Set new password (8-128 chars)
6. **Automatic Re-wrapping**: `rewrap_feks_for_user()` updates all `.crypt_meta` files:
   - Unwraps FEKs with old user key
   - Re-wraps FEKs with new user key
   - Preserves all file access permissions

### Security Features
- **Token-Based**: Temporary token prevents unauthorized resets
- **Encrypted Storage**: Security questions encrypted with fixed key (`SECURITY_QUESTIONS_KEY`)
- **No Plaintext**: Answers never stored or transmitted in plaintext
- **Audit Logging**: All recovery attempts logged with timestamps

## ⚙️ Configuration

### Security Parameters (in `secure_folder_v.1.py`)

```python
# Session Management
SESSION_TIMEOUT = timedelta(hours=2)        # Session duration before auto-logout
MAX_LOGIN_ATTEMPTS = 5                       # Lockout threshold
LOCKOUT_DURATION = timedelta(minutes=15)     # Lockout period after failed attempts

# Cryptographic Parameters
PBKDF2_ITERATIONS = 100_000                  # Key derivation iterations (SHA256)
BCRYPT_ROUNDS = 12                           # Password hashing rounds

# Security Questions
SECURITY_QUESTIONS_KEY = b"SecureQKey32BytesLongExactlyNow!"  # 32-byte AES key
```

### Adjusting Security Levels

#### Higher Security (Slower Performance)
Recommended for high-value data or compliance requirements:
```python
PBKDF2_ITERATIONS = 200_000  # Double the iterations
BCRYPT_ROUNDS = 14           # 4x slower hashing
SESSION_TIMEOUT = timedelta(hours=1)  # Shorter sessions
```

#### Faster Performance (Lower Security)
For development/testing or low-risk environments:
```python
PBKDF2_ITERATIONS = 50_000   # Half the iterations
BCRYPT_ROUNDS = 10           # 4x faster hashing
SESSION_TIMEOUT = timedelta(hours=4)  # Longer sessions
```

⚠️ **Warning**: Changing cryptographic parameters affects existing data:
- PBKDF2/bcrypt changes require password re-registration
- Session timeout changes apply to new sessions only

## 🛠️ Development

### Running in Development Mode

```bash
# Set environment variable (optional, for Flask debug features)
export FLASK_ENV=development

# Run the application
python secure_folder_v.1.py
```

The application will:
1. Start Flask server on `http://127.0.0.1:5000`
2. Open pywebview desktop window
3. Log all operations to console with timestamps

### Testing API Endpoints

```bash
# Test registration (first user becomes admin)
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123!",
    "security_questions": [
      {"question": "What was the name of your first pet?", "answer": "fluffy"},
      {"question": "What city were you born in?", "answer": "new york"}
    ]
  }'

# Test login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"username": "admin", "password": "SecurePass123!"}'

# Test whoami (requires session cookie)
curl -X GET http://localhost:5000/whoami \
  -b cookies.txt

# Test security questions retrieval
curl -X GET http://localhost:5000/security_questions

# Test forgot password flow
curl -X POST http://localhost:5000/forgot_password/questions \
  -H "Content-Type: application/json" \
  -d '{"username": "admin"}'

# Test logout
curl -X POST http://localhost:5000/logout \
  -b cookies.txt
```

### Admin Operations Testing

```bash
# List all users (admin only)
curl -X GET http://localhost:5000/admin/users_full \
  -b cookies.txt

# Set vault folder
curl -X POST http://localhost:5000/admin/set_vault \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"path": "/path/to/vault"}'

# List encrypted files in vault
curl -X POST http://localhost:5000/admin/list_files \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"vault_path": "/path/to/vault"}'

# Grant file access to user
curl -X POST http://localhost:5000/admin/grant_file_access \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "file_path": "/path/to/vault/file.enc",
    "username": "regularuser"
  }'

# Promote user to admin
curl -X POST http://localhost:5000/admin/promote \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"username": "regularuser"}'
```

### Debugging Tips

```python
# Enable verbose logging in secure_folder_v.1.py
logging.basicConfig(
    level=logging.DEBUG,  # Change from INFO to DEBUG
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Inspect session keys (in Python REPL)
from secure_folder_v.1 import _session_keys, _users_cache
print(_session_keys)
print(_users_cache)

# Check file paths
from secure_folder_v.1 import HOME_DIR, ADMIN_KEY_FILE, USERS_FILE_ENC
print(f"Home: {HOME_DIR}")
print(f"Admin key exists: {ADMIN_KEY_FILE.exists()}")
print(f"Users DB exists: {USERS_FILE_ENC.exists()}")
```

## 📝 Best Practices

### For Users
- ✅ **Use Strong Passwords**: 12+ characters with mixed case, numbers, symbols
- ✅ **Memorable Security Answers**: Choose answers you'll remember but aren't publicly known
- ✅ **Logout Properly**: Always logout when finished, especially on shared computers
- ✅ **Backup Decrypted Files**: Keep copies of important files outside the vault
- ✅ **Verify Before Encrypting**: Ensure files are complete before encryption (process is destructive)
- ✅ **Test Recovery**: Periodically test password recovery to ensure questions/answers work

### For Administrators
- ✅ **Secure Recovery Key**: Store `~/.secure_folder_admin_recovery.bin` in encrypted backup
- ✅ **Review Access Permissions**: Regularly audit file access grants using `/admin/users_full`
- ✅ **Monitor Logs**: Watch console output for failed login attempts and errors
- ✅ **Test Backup/Recovery**: Practice full system restore procedures quarterly
- ✅ **Update Dependencies**: Keep `flask`, `cryptography`, `bcrypt` packages current
- ✅ **Limit Admin Accounts**: Promote users to admin only when necessary
- ✅ **Document Vault Location**: Record vault path in secure location for disaster recovery

### Security Hardening (Production)
```python
# In secure_folder_v.1.py, add these for production deployment:
app.config['SESSION_COOKIE_SECURE'] = True    # HTTPS only
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # No cross-site cookies

# Add CSRF protection (requires flask-wtf):
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Add rate limiting (requires flask-limiter):
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: session.get('username', 'anonymous'))
```

## ⚠️ Warnings

### Danger Zone: Reset App Function

The `/admin/reset_app` endpoint performs a **complete factory reset**:

**What it does:**
1. Decrypts all `.enc` files in vault (if admin credentials available)
2. Removes all `.crypt_meta` metadata files
3. Deletes `~/.secure_folder_admin_key.bin`
4. Deletes `~/.secure_folder_admin_recovery.bin`
5. Deletes `~/.secure_folder_vault.txt`
6. Deletes `~/.secure_folder_users.json.enc`
7. Clears in-memory caches (`_users_cache`, `_session_keys`, `_admin_key`)
8. Ends current session

**⚠️ THIS ACTION CANNOT BE UNDONE!**

Only use when:
- Starting fresh with new configuration
- All data has been backed up externally
- Emergency recovery situation

### Important Operational Notes

| Behavior | Description |
|----------|-------------|
| **Encryption** | Original files deleted, `.enc` files created |
| **Decryption** | `.enc` files deleted, original files restored |
| **Password Loss** | Recoverable via security questions |
| **Admin Key Loss** | Requires full app reset (data loss) |
| **Vault Corruption** | Manual intervention required |
| **Session Expiry** | 2-hour timeout, auto-logout |

### Data Integrity Considerations

- **No Versioning**: Encrypted files overwrite without version history
- **Atomic Operations**: Encryption/decryption are not atomic (power failure = data loss risk)
- **Single Vault**: All users share same vault folder (no per-user isolation)
- **Metadata Exposure**: `.crypt_meta` files are plaintext (reveal file names, user access)

### Known Limitations

1. **No HTTPS by Default**: Flask development server runs on HTTP only
2. **No Email Recovery**: Password reset requires local access only
3. **No Audit Trail**: No persistent logging of operations
4. **In-Memory Rate Limiting**: Login attempts reset on application restart
5. **No File Size Limits**: Large files may cause memory issues
6. **Single-Threaded Encryption**: No parallel processing for bulk operations

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied Errors
**Symptom**: Cannot create or access files in home directory  
**Solution**: 
- Application stores files in `~` (home directory) to avoid permission issues
- Ensure write access: `ls -la ~ | grep secure_folder`
- On Linux/Mac: `chmod 700 ~/.secure_folder_*`

#### Login Fails After Password Reset
**Symptom**: Valid credentials rejected after password change  
**Solution**:
- Clear browser cache and cookies
- Try incognito/private browsing mode
- Restart the application (clears session cache)
- Wait 15 minutes if rate-limited

#### Encryption/Decryption Errors
**Symptom**: Operation fails mid-process  
**Solution**:
- Verify vault folder is accessible: `ls -la /path/to/vault`
- Check disk space: `df -h`
- Ensure file is not in use by another program
- Check for `.enc` or `.crypt_meta` file corruption

#### Application Won't Start
**Symptom**: Python script exits immediately or pywebview window doesn't open  
**Solution**:
```bash
# Check Python version (3.8+ required)
python --version

# Verify dependencies installed
pip list | grep -E "flask|cryptography|bcrypt|pywebview"

# Check for port conflicts (port 5000)
netstat -an | grep 5000
# or
lsof -i :5000

# Test Flask server directly (without pywebview)
python -c "from secure_folder_v.1 import app; app.run()"

# Check for missing system libraries (pywebview requires gtk/qt)
# On Ubuntu/Debian:
sudo apt-get install python3-gi gir1.2-gtk-3.0
# On macOS:
brew install pyobjc
```

#### Rate Limiting Lockout
**Symptom**: "Account locked" message after failed logins  
**Solution**:
- Wait 15 minutes for automatic reset
- Restart application (clears in-memory `_login_attempts`)
- Use password recovery if credentials forgotten

#### Corrupted User Database
**Symptom**: "Could not decrypt user database" warning on startup  
**Solution**:
- Indicates wrong admin key or corrupted `.secure_folder_users.json.enc`
- If you have backup: restore from backup
- Otherwise: use `/admin/reset_app` to start fresh (data loss!)

### Diagnostic Commands

```bash
# Check all Secure Folder files in home directory
ls -la ~ | grep secure_folder

# View vault path configuration
cat ~/.secure_folder_vault.txt

# Check if admin key exists
test -f ~/.secure_folder_admin_key.bin && echo "Admin key exists" || echo "No admin key"

# Test cryptography installation
python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('OK')"

# Test bcrypt installation
python -c "import bcrypt; print(bcrypt.gensalt())"

# View application logs (console output)
python secure_folder_v.1.py 2>&1 | tee app.log
```

## 📄 License

This project is provided **as-is** for educational and personal use. No warranty expressed or implied.

## 🤝 Contributing

Contributions welcome! Please ensure:
- ✅ Code follows existing style and conventions
- ✅ Security features are not compromised
- ✅ Changes are tested thoroughly with unit tests
- ✅ Documentation updated for new features
- ✅ No breaking changes without major version bump

### Pull Request Guidelines
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📞 Support

For issues or questions:
1. ✅ Check this README troubleshooting section
2. ✅ Review console logs for error messages
3. ✅ Verify configuration settings match requirements
4. ✅ Test with minimal setup (single user, small files)
5. ✅ Check `IMPROVEMENTS.md` for known issues and recommendations

### Reporting Bugs
When reporting issues, please include:
- Python version (`python --version`)
- OS and version
- Installed package versions (`pip list`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output

---

**Secure Folder v.1** - Built with ❤️ using Flask, cryptography, and modern web technologies

**Version**: 1.0 | **Last Updated**: 2024 | **Python**: 3.8+
