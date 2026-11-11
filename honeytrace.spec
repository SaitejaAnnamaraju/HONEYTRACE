# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Spec file for HONEYTRACE Standalone Executable
import sys
from pathlib import Path

block_cipher = None
ROOT_DIR = Path.cwd()

added_files = [
    (str(ROOT_DIR / "app.py"), "."),
    (str(ROOT_DIR / "dashboard"), "dashboard"),
    (str(ROOT_DIR / "core"), "core"),
    (str(ROOT_DIR / "honeypots"), "honeypots"),
    (str(ROOT_DIR / "simulation"), "simulation"),
    (str(ROOT_DIR / "assets"), "assets"),
    (str(ROOT_DIR / "data"), "data"),
    (str(ROOT_DIR / "reports"), "reports"),
]

a = Analysis(
    ['launcher.py'],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'streamlit',
        'streamlit.web.bootstrap',
        'plotly',
        'plotly.express',
        'plotly.graph_objects',
        'pandas',
        'flask',
        'requests',
        'PIL',
        'fpdf',
        'pytest',
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
    [],
    exclude_binaries=True,
    name='HONEYTRACE',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT_DIR / 'assets' / 'logo.png') if (ROOT_DIR / 'assets' / 'logo.png').exists() else None
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='HONEYTRACE',
)

