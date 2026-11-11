"""
HONEYTRACE - Automated ZIP Distribution Packager
Creates a clean, portable distribution package (HONEYTRACE_Demonstration_Suite.zip)
excluding bytecode caches, git tracking files, and virtual environment artifacts.
"""

import os
import shutil
import sys
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
DIST_DIR = ROOT_DIR / "dist"
ZIP_NAME = "HONEYTRACE_Demonstration_Suite.zip"
OUTPUT_ZIP_DIST = DIST_DIR / ZIP_NAME
OUTPUT_ZIP_ROOT = ROOT_DIR / "HONEYTRACE.zip"

EXCLUDE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode"
}

EXCLUDE_EXTS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".tmp",
    ".log",
    ".zip"
}


def build_distribution_zip():
    print("=" * 65)
    print("        HONEYTRACE - Distribution Packaging Utility")
    print("=" * 65)
    print(f"[*] Root Directory: {ROOT_DIR}")
    
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    
    for old_zip in [OUTPUT_ZIP_DIST, OUTPUT_ZIP_ROOT]:
        if old_zip.exists():
            old_zip.unlink()
            print(f"[*] Removed previous archive: {old_zip.name}")

    total_files = 0
    total_size = 0

    with zipfile.ZipFile(OUTPUT_ZIP_DIST, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(ROOT_DIR):
            # Prune excluded directories in-place
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in files:
                file_path = Path(root) / file
                
                # Check exclusions
                if file_path.suffix.lower() in EXCLUDE_EXTS:
                    continue

                rel_path = file_path.relative_to(ROOT_DIR)
                # Ensure files are placed inside a top-level HONEYTRACE/ folder in the zip
                archive_name = Path("HONEYTRACE") / rel_path

                zipf.write(file_path, arcname=str(archive_name))
                total_files += 1
                total_size += file_path.stat().st_size

    # Copy to root HONEYTRACE.zip for convenience
    shutil.copy2(OUTPUT_ZIP_DIST, OUTPUT_ZIP_ROOT)

    zip_size_mb = OUTPUT_ZIP_DIST.stat().st_size / (1024 * 1024)
    raw_size_mb = total_size / (1024 * 1024)

    print(f"[+] Successfully generated portable ZIP distribution:")
    print(f"    - Primary Zip:    {OUTPUT_ZIP_ROOT}")
    print(f"    - Dist Directory: {OUTPUT_ZIP_DIST}")
    print(f"    - Packaged Files: {total_files}")
    print(f"    - Uncompressed:   {raw_size_mb:.2f} MB")
    print(f"    - Compressed:     {zip_size_mb:.2f} MB")
    print("=" * 65)
    print("Packaging complete. Distribute HONEYTRACE.zip to examiners or friends.")


if __name__ == "__main__":
    build_distribution_zip()

