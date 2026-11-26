"""Load and normalize .searchsploit_rc configuration."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

_ARRAY_RE = re.compile(
    r'^(files_array|name_array|path_array|git_array|package_array)\+=\("?(.*?)"?\)$'
)


@dataclass
class Database:
    files: str
    path: Path
    name: str
    git: str
    package: str = ""

    @property
    def csv_path(self) -> Path:
        return self.path / self.files

    def exists(self) -> bool:
        return self.csv_path.is_file()


def candidate_rc_paths() -> List[Path]:
    """Locations checked for .searchsploit_rc, in priority order."""
    paths: List[Path] = []
    home = Path.home()
    paths.append(home / ".searchsploit_rc")
    paths.append(home / ".local" / ".searchsploit_rc")

    # Package-bundled / repo-local templates
    pkg_dir = Path(__file__).resolve().parent
    paths.append(pkg_dir / "data" / ".searchsploit_rc")
    paths.append(pkg_dir.parent / ".searchsploit_rc")

    # Frozen (PyInstaller) next to executable
    if getattr(sys, "frozen", False):
        paths.insert(0, Path(sys.executable).resolve().parent / ".searchsploit_rc")

    # Explicit env override
    env = os.environ.get("SEARCHSPLOIT_RC")
    if env:
        paths.insert(0, Path(env))

    return paths


def find_rc_file() -> Optional[Path]:
    for path in candidate_rc_paths():
        if path.is_file():
            return path
    return None


def _parse_rc_line(line: str) -> Optional[tuple]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = _ARRAY_RE.match(line)
    if not match:
        return None
    key, value = match.group(1), match.group(2)
    # Strip trailing bash-style quote leftovers
    value = value.rstrip('"').rstrip("'")
    return key, value


def load_databases(rc_path: Optional[Path] = None) -> List[Database]:
    """Parse RC file into Database entries; drop missing CSV paths."""
    path = rc_path or find_rc_file()
    if path is None:
        locations = "\n".join(f'  "{p}"' for p in candidate_rc_paths())
        raise FileNotFoundError(
            "Cannot find .searchsploit_rc.\n"
            "Place it in one of:\n"
            f"{locations}\n"
            "Or run scripts/install.ps1 to create one."
        )

    files_array: List[str] = []
    name_array: List[str] = []
    path_array: List[str] = []
    git_array: List[str] = []
    package_array: List[str] = []

    text = path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        parsed = _parse_rc_line(raw)
        if not parsed:
            continue
        key, value = parsed
        if key == "files_array":
            files_array.append(value)
        elif key == "name_array":
            name_array.append(value)
        elif key == "path_array":
            path_array.append(value)
        elif key == "git_array":
            git_array.append(value)
        elif key == "package_array":
            package_array.append(value)

    count = len(files_array)
    databases: List[Database] = []
    for i in range(count):
        db = Database(
            files=files_array[i],
            path=Path(path_array[i]).expanduser().resolve()
            if i < len(path_array)
            else Path("."),
            name=name_array[i] if i < len(name_array) else f"DB{i}",
            git=git_array[i] if i < len(git_array) else "",
            package=package_array[i] if i < len(package_array) else "",
        )
        if db.exists():
            databases.append(db)

    return databases


def write_rc(
    exploitdb_path: Path,
    papers_path: Optional[Path] = None,
    dest: Optional[Path] = None,
) -> Path:
    """Write a Windows-oriented .searchsploit_rc for the given DB roots."""
    dest = dest or (Path.home() / ".searchsploit_rc")
    edb = exploitdb_path.resolve().as_posix()
    papers = (
        papers_path.resolve().as_posix()
        if papers_path
        else Path("C:/exploitdb-papers").as_posix()
    )
    content = f"""##-- Program Settings
progname="$( basename "$0" )"

##-- Exploits
files_array+=("files_exploits.csv")
path_array+=("{edb}")
name_array+=("Exploit")
git_array+=("https://gitlab.com/exploit-database/exploitdb.git")
package_array+=("exploitdb")

##-- Shellcodes
files_array+=("files_shellcodes.csv")
path_array+=("{edb}")
name_array+=("Shellcode")
git_array+=("https://gitlab.com/exploit-database/exploitdb.git")
package_array+=("exploitdb")

##-- Papers
files_array+=("files_papers.csv")
path_array+=("{papers}")
name_array+=("Paper")
git_array+=("https://gitlab.com/exploit-database/exploitdb-papers.git")
package_array+=("exploitdb-papers")
"""
    dest.write_text(content, encoding="utf-8")
    return dest
