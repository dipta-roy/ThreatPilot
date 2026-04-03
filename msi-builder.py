import sys
import os
import re
from pathlib import Path

sys.setrecursionlimit(10000)

import PySide6.QtCore
import PySide6.QtGui
import PySide6.QtWidgets
import PySide6.QtNetwork

from cx_Freeze import setup, Executable

icon_png = Path("threatpilot/resources/app-icon.png")
icon_ico = Path("threatpilot/resources/app-icon.ico")

if icon_png.exists() and not icon_ico.exists():
    try:
        from PIL import Image
        img = Image.open(icon_png)
        img.save(icon_ico, format='ICO', sizes=[(256, 256)])
        print("Successfully converted app-icon.png to app-icon.ico")
    except ImportError:
        print("WARNING: Pillow not installed, skipping ICO conversion. Executable may lack icon.")
    except Exception as e:
        print(f"Error converting icon: {e}")

version_str = "1.0.0"
main_path = Path("main.py")
if main_path.exists():
    content = main_path.read_text(encoding="utf-8")
    m = re.search(r'app\.setApplicationVersion\("([^"]+)"\)', content)
    if m:
        raw_version = m.group(1)
        numeric_only = re.sub(r'[^\d\.]', '', raw_version).strip('.')
        parts = numeric_only.split('.') if numeric_only else ['1', '0', '0']
        while len(parts) < 3:
            parts.append('0')
        version_str = '.'.join(parts[:3])

print(f"Building MSI using parsed version: {version_str}")

build_exe_options = {
    "packages": [
        "os", "sys", "threatpilot", "threatpilot.ai", "threatpilot.ui", 
        "threatpilot.core", "threatpilot.utils", "threatpilot.detection",
        "threatpilot.config", "threatpilot.export", "threatpilot.risk",
        "pydantic", "pydantic_core", "httpx", "cryptography", "keyring", "shiboken6",
        "dotenv", "openpyxl", "certifi", "anyio", "idna", "sniffio", "httpcore",
        "PIL", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets", 
        "PySide6.QtNetwork", "PySide6.QtPrintSupport", "PySide6.QtXml", "PySide6.QtSvg"
    ],
    "include_files": [
        ("threatpilot/resources", "threatpilot/resources"),
    ],
    "excludes": [
        "tkinter", "unittest", "cv2", "numpy", 
        "pandas", "pyarrow", "matplotlib", 
        "scipy", "notebook", "email", "http.server",
        "xmlrpc", "PySide6.QtWebEngine", "PySide6.QtWebEngineCore",
        "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.Qt3D",
        "PySide6.QtRemoteObjects", "PySide6.QtCharts", "PySide6.QtSql",
        "PySide6.QtPositioning", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
        "PySide6.QtWebChannel", "PySide6.QtWebengineCore"
    ],
    "bin_excludes": [
        "Qt6WebEngineCore.dll", "Qt6Pdf.dll", "Qt6Quick.dll", "Qt6Qml.dll",
        "Qt6QuickWidgets.dll", "Qt63DCore.dll", "Qt63DRender.dll",
        "Qt6Charts.dll", "Qt6Sql.dll", "Qt6Positioning.dll", "Qt6Multimedia.dll",
        "Qt6MultimediaWidgets.dll", "Qt6Designer.dll", "opengl32sw.dll",
        "D3DCompiler_47.dll", "libGLESv2.dll", "libEGL.dll"
    ],
    "include_msvcr": True,
    "optimize": 2,
    "zip_include_packages": [],
    "zip_exclude_packages": ["*"],
}

base = None
if sys.platform == "win32":
    base = "Win32GUI"

shortcut_table = [
    ("DesktopShortcut",        
     "DesktopFolder",          
     "ThreatPilot",            
     "TARGETDIR",              
     "[TARGETDIR]ThreatPilot.exe",
     None,                     
     None,                     
     None,                     
     None,                     
     None,                     
     None,                     
     'TARGETDIR'               
     ),
    ("StartMenuShortcut",      
     "ProgramMenuFolder",      
     "ThreatPilot",            
     "TARGETDIR",              
     "[TARGETDIR]ThreatPilot.exe",
     None,                     
     None,                     
     None,                     
     None,                     
     None,                     
     None,                     
     'TARGETDIR'               
     ),
]

bdist_msi_options = {
    "upgrade_code": "{A0B1C2D3-E4F5-6A7B-8C9D-0E1F2A3B4C5D}", 
    "add_to_path": True,
    "initial_target_dir": r"[LocalAppDataFolder]\ThreatPilot",
    "data": {"Shortcut": shortcut_table},
    "all_users": False,
    "install_icon": str(icon_ico) if icon_ico.exists() else None,
}

setup(
    name="ThreatPilot",
    version=version_str,
    description="ThreatPilot - AI Driven Threat Modeling",
    author="Dipta Roy",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=[
        Executable(
            script="main.py",
            base=base,
            target_name="ThreatPilot.exe",
            icon=str(icon_ico) if icon_ico.exists() else None,
            uac_admin=False
        )
    ]
)
