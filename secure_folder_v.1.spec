# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['secure_folder_v.1.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('index.html', '.'),   # Include the HTML frontend
        ('favicon.ico', '.')   # Include the favicon (also used as application icon)
    ],
    hiddenimports=[
        'webview',
        'cryptography',
        'cryptography.hazmat.primitives',
        'bcrypt',
        'flask',
        'jinja2',
        'markupsafe',
        'itsdangerous',
        'werkzeug',
        'click',
        'tkinter'  # used for folder browser
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='FolderLocker',   # Output executable name (change if desired)
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='favicon.ico'      # Application icon from favicon.ico
)