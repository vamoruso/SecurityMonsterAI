# -*- mode: python ; coding: utf-8 -*-

import os
import pyfiglet

block_cipher = None

# Trova la directory dei font di pyfiglet
pyfiglet_fonts = os.path.join(os.path.dirname(pyfiglet.__file__), 'fonts')

a = Analysis(
    ['SecurityMonster.py'],
    pathex=[],
    binaries=[],
    datas=[
         (pyfiglet_fonts, 'pyfiglet/fonts'),  # ← CRITICO: Includi i font
        ('SecModule', 'SecModule'),  # Includi la cartella SecModule
        # Se hai altri file/cartelle, aggiungili qui
    ],
    hiddenimports=[
        'SecModule.common_utils',  # Importazione nascosta
        'SecModule.file_reader',
        'SecModule.source_code_analyzer',
        'SecModule.yara_analyzer',
        'SecModule.clamav_analyzer',
        'SecModule.leaf_analyzer',
        'pyfiglet',
        'pyfiglet.fonts',
        'multiprocessing',
        'multiprocessing.pool',
        # Aggiungi altri moduli nascosti se necessario
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SecurityMonster',
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
