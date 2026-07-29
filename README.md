# 🔐 Secure Folder v7

A secure file encryption application with multi-user support, role-based access control, and enterprise-grade security features. Built with Flask (backend) and vanilla JavaScript (frontend), using AES-GCM encryption for file protection.

## 📋 Features

### Core Capabilities
- **File Encryption/Decryption**: Encrypt folders with AES-GCM-256 encryption
- **Multi-User System**: Support for multiple users with individual accounts
- **Role-Based Access Control**: Admin and regular user roles
- **Fine-Grained File Access Control**: Admins can grant/revoke file access per user
- **Password Recovery**: Security question-based account recovery system

### Security Features
- **AES-GCM-256 Encryption**: Industry-standard authenticated encryption
- **PBKDF2-HMAC-SHA256**: Key derivation with 100,000 iterations
- **bcrypt Password Hashing**: 12 rounds for secure password storage
- **Session Management**: HTTPOnly cookies with 2-hour timeout
- **Rate Limiting**: Account lockout after 5 failed login attempts (15-minute lockout)
- **Input Validation**: Comprehensive server-side validation
- **User Enumeration Prevention**: Generic error messages for login failures
- **Secure Key Storage**: Admin key and user database encrypted at rest

### User Experience
- **Modern UI**: Dark theme with responsive design
- **Real-time Feedback**: Toast notifications for success/error messages
- **Client-Side Validation**: Immediate input validation
- **Folder Browser**: Native folder selection dialog
- **Search Functionality**: Filter users and files quickly

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   index.html    │────▶│  secure_folder   │────▶│  File System    │
│   (Frontend)    │     │     v7.py        │     │  (Encrypted)    │
│                 │◀────│   (Flask App)    │◀────│                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Home Directory  │
                        │  - admin_key     │
                        │  - users.json.enc│
                        │  - vault.txt     │
                        └──────────────────┘
```

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Dependencies

Install required packages:

```bash
pip install flask cryptography bcrypt pywebview
```

Or install from requirements (if available):

```bash
pip install -r requirements.txt
```

### Required Packages
- `flask` - Web framework
- `cryptography` - AES-GCM encryption, PBKDF2 key derivation
- `bcrypt` - Password hashing
- `pywebview` - Native folder browser dialogs

## 🚀 Quick Start

### First Run (Admin Setup)

1. **Start the application:**
   ```bash
   python secure_folder_v7.py
   ```

2. **Open your browser** and navigate to `http://localhost:5000`

3. **Register as Admin:**
   - The first user to register automatically becomes an administrator
   - Choose a strong password (minimum 8 characters)
   - Select 2-3 security questions for account recovery

4. **Set Vault Folder:**
   - As admin, configure the shared vault folder location
   - This folder will store all encrypted files

### Regular Usage

#### For Users:
1. **Login** with your credentials
2. **Enter folder path** you want to encrypt/decrypt
3. **Click Encrypt** to secure your files
4. **Click Decrypt** to access encrypted files

#### For Admins:
In addition to user capabilities, admins can:
- **Manage Users**: View all registered users
- **Grant File Access**: Allow specific users to access specific encrypted files
- **Revoke File Access**: Remove user access to files
- **Promote Users**: Elevate users to admin role
- **Configure Vault**: Set the shared vault folder location
- **Reset App**: Complete factory reset (use with caution!)

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

1. **File Encryption Key (FEK)**: Random 256-bit key generated per file
2. **Key Wrapping**: FEK encrypted with user's derived key
3. **Access Control**: Multiple wrapped FEKs stored for authorized users
4. **Admin Override**: Admin can access any file via wrapped user keys

### Key Hierarchy

```
Admin Key (derived from admin password)
    ├── User Key Wrappings (for access control)
    └── Recovery Key (encrypted backup)

User Key (derived from user password)
    └── Wrapped FEKs (for authorized files)

File Encryption Key (FEK)
    └── Encrypts actual file content (AES-GCM)
```

### Data Storage

All sensitive data stored in user's home directory:
- `~/.secure_folder_admin_key.bin` - Admin encryption key
- `~/.secure_folder_users.json.enc` - Encrypted user database
- `~/.secure_folder_vault.txt` - Vault folder path
- `~/.secure_folder_admin_recovery.bin` - Admin recovery key

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

The application includes a self-service password recovery system:

1. **Security Questions**: Users select 2-3 questions during registration
2. **Answer Verification**: Answers are case-insensitive and trimmed
3. **Token-Based Reset**: Temporary token issued after verification
4. **Automatic Re-wrapping**: All file keys re-wrapped with new password

### Recovery Process
1. Click "Forgot Password?" on login screen
2. Enter username
3. Answer security questions
4. Set new password
5. Login with new credentials

## ⚙️ Configuration

### Security Parameters (in `secure_folder_v7.py`)

```python
SESSION_TIMEOUT = timedelta(hours=2)        # Session duration
MAX_LOGIN_ATTEMPTS = 5                       # Lockout threshold
LOCKOUT_DURATION = timedelta(minutes=15)     # Lockout period
PBKDF2_ITERATIONS = 100_000                  # Key derivation iterations
BCRYPT_ROUNDS = 12                           # Password hashing rounds
```

### Adjusting Security Levels

For higher security (slower performance):
```python
PBKDF2_ITERATIONS = 200_000
BCRYPT_ROUNDS = 14
```

For faster performance (lower security):
```python
PBKDF2_ITERATIONS = 50_000
BCRYPT_ROUNDS = 10
```

## 🛠️ Development

### Running in Development Mode

```bash
export FLASK_ENV=development
python secure_folder_v7.py
```

### Testing

```bash
# Test registration
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"securepass123","security_questions":[...]}'

# Test login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"securepass123"}'
```

## 📝 Best Practices

### For Users
- ✅ Use strong, unique passwords (12+ characters recommended)
- ✅ Choose security questions with memorable but non-obvious answers
- ✅ Logout when finished, especially on shared computers
- ✅ Regularly backup important decrypted files

### For Administrators
- ✅ Store admin recovery key in a secure location
- ✅ Regularly review user access permissions
- ✅ Monitor login attempts in logs
- ✅ Test backup and recovery procedures
- ✅ Keep the application updated

## ⚠️ Warnings

### Danger Zone
The "Reset App" function will:
- Delete all user accounts and passwords
- Remove admin keys and vault settings
- Decrypt all encrypted files
- Remove encryption metadata

**This action cannot be undone!** Use only when necessary.

### Important Notes
- Encrypted files are deleted after decryption (original restored)
- Original files are deleted after encryption (.enc file created)
- Lost passwords can be recovered via security questions
- Lost admin key requires complete app reset

## 🐛 Troubleshooting

### Common Issues

**Permission Denied Errors**
- Application stores files in home directory to avoid permission issues
- Ensure write access to home directory

**Login Fails After Password Reset**
- Clear browser cache and cookies
- Try incognito/private browsing mode

**Encryption/Decryption Errors**
- Verify vault folder is accessible
- Check disk space availability
- Ensure file is not in use by another program

**Application Won't Start**
```bash
# Check Python version
python --version  # Should be 3.8+

# Verify dependencies
pip list | grep -E "flask|cryptography|bcrypt|pywebview"

# Check for port conflicts
netstat -an | grep 5000
```

## 📄 License

This project is provided as-is for educational and personal use.

## 🤝 Contributing

Contributions welcome! Please ensure:
- Code follows existing style
- Security features are not compromised
- Changes are tested thoroughly

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Review logs in console output
3. Verify configuration settings

---

**Built with ❤️ using Flask, cryptography, and modern web technologies**
