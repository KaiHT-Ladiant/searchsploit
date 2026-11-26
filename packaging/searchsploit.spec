# -*- mode: python ; coding: utf-8 -*-
# Build: pyinstaller packaging/searchsploit.spec

from pathlib import Path

block_cipher = None
root = Path(SPECPATH).parent.resolve()

a = Analysis(
    [str(root / "searchsploit" / "__main__.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "searchsploit" / "data" / ".searchsploit_rc"), "searchsploit/data"),
    ],
    hiddenimports=["colorama", "pyperclip"],
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
    a.zipfiles,
    a.datas,
    [],
    name="searchsploit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
