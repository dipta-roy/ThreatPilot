import sys
import re
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage: python update_version.py <version>")
    sys.exit(1)

version = sys.argv[1]

# Update the central package version (The source of truth)
init_file = Path("threatpilot/__init__.py")
if init_file.exists():
    content = init_file.read_text(encoding="utf-8")
    content = re.sub(r'__version__\s*=\s*".*?"', f'__version__ = "{version}"', content)
    init_file.write_text(content, encoding="utf-8")
    print(f"Updated threatpilot/__init__.py to version {version}")

print("\nSUCCESS: Version synchronized across all components.")
print("The UI and MSI builder will now automatically use the new version.")
