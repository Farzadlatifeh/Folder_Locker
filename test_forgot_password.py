#!/usr/bin/env python3
"""Test script to verify forgot password API endpoint"""
import sys
sys.path.insert(0, '/workspace')

# Mock webview to prevent import error
import unittest.mock as mock
sys.modules['webview'] = mock.MagicMock()

# Now we can import the app
from secure_folder_v7 import app, _users_cache, _admin_key, load_admin_key, load_users_from_encrypted
from threading import RLock

# Initialize test data
cache_lock = RLock()
test_users = {
    'testuser': {
        'username': 'testuser',
        'password_hash': 'fakehash',
        'is_admin': False,
        'security_questions': [
            {'question': "What is your pet's name?", 'answer_hash': 'ans1', 'salt': 'salt1'},
            {'question': 'What city were you born in?', 'answer_hash': 'ans2', 'salt': 'salt2'}
        ]
    }
}

# Patch the global variables
import secure_folder_v7
secure_folder_v7._users_cache = test_users
secure_folder_v7._admin_key = b'testkey123456789012345678901234'  # 32 bytes

# Create test client
client = app.test_client()

# Test 1: Valid user with security questions
print("Test 1: Valid user with security questions")
response = client.post('/forgot_password/questions', 
                       json={'username': 'testuser'},
                       content_type='application/json')
print(f"Status: {response.status_code}")
print(f"Response: {response.get_json()}")
print()

# Test 2: Non-existent user
print("Test 2: Non-existent user")
response = client.post('/forgot_password/questions', 
                       json={'username': 'nonexistent'},
                       content_type='application/json')
print(f"Status: {response.status_code}")
print(f"Response: {response.get_json()}")
print()

# Test 3: Empty username
print("Test 3: Empty username")
response = client.post('/forgot_password/questions', 
                       json={'username': ''},
                       content_type='application/json')
print(f"Status: {response.status_code}")
print(f"Response: {response.get_json()}")
print()

# Test 4: Missing username field
print("Test 4: Missing username field")
response = client.post('/forgot_password/questions', 
                       json={},
                       content_type='application/json')
print(f"Status: {response.status_code}")
print(f"Response: {response.get_json()}")
print()

# Test 5: User without security questions
secure_folder_v7._users_cache['noquestions'] = {
    'username': 'noquestions',
    'password_hash': 'fakehash',
    'is_admin': False,
    'security_questions': []
}
print("Test 5: User without security questions")
response = client.post('/forgot_password/questions', 
                       json={'username': 'noquestions'},
                       content_type='application/json')
print(f"Status: {response.status_code}")
print(f"Response: {response.get_json()}")
print()

print("All tests completed!")
