import sys
sys.path.insert(0, '.')

# Mock webview to prevent import errors
import unittest.mock as mock
sys.modules['webview'] = mock.MagicMock()

from secure_folder_v7 import app, load_admin_key, _users_cache, save_users_encrypted, _admin_key, derive_key, bcrypt, secrets, SECURITY_QUESTIONS
import json

# Start Flask directly
if __name__ == "__main__":
    print("Starting Flask server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
