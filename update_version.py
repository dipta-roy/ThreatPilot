import sys
import re
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage: python update_version.py <version>")
    sys.exit(1)

version = sys.argv[1]

# 1. Update main.py
main_file = Path("main.py")
if main_file.exists():
    content = main_file.read_text(encoding="utf-8")
    content = re.sub(r'app\.setApplicationVersion\(".*?"\)', f'app.setApplicationVersion("{version}")', content)
    main_file.write_text(content, encoding="utf-8")
    print(f"Updated main.py to version {version}")

# 2. Update about_dialog.py
about_file = Path("threatpilot/ui/about_dialog.py")
if about_file.exists():
    content = about_file.read_text(encoding="utf-8")
    # Search for version_badge = QLabel("  v0.5-beta  ")
    content = re.sub(r'version_badge = QLabel\("\s*v.*?\s*"\)', f'version_badge = QLabel("  v{version}  ")', content)
    about_file.write_text(content, encoding="utf-8")
    print(f"Updated about_dialog.py to version {version}")
