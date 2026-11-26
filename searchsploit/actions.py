"""Command actions: path, mirror, examine, update, nmap helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from searchsploit.config import Database
from searchsploit.csvdb import ExploitRecord, find_by_id


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success."""
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            # Prefer clip.exe; keep process brief
            proc = subprocess.run(
                ["clip"],
                input=text.encode("utf-16-le"),
                check=False,
                capture_output=True,
            )
            return proc.returncode == 0
        except OSError:
            return False
    return False


def show_path(databases: Sequence[Database], edb_id: int) -> int:
    record = find_by_id(databases, edb_id)
    if record is None:
        print(f"{edb_id} does not exist. Please double check that this is the correct id.")
        return 1

    path = str(record.full_path)
    print(f"  Exploit: {record.title}")
    print(f"      URL: {record.www_url}")
    print(f"     Path: {path}")
    if record.full_path.is_file():
        size = record.full_path.stat().st_size
        print(f"File Size: {size} bytes")
    if copy_to_clipboard(path):
        print(f"\nCopied EDB-ID #{record.edb_id}'s path to the clipboard.")
    return 0


def mirror(databases: Sequence[Database], edb_id: int, dest_dir: Optional[Path] = None) -> int:
    record = find_by_id(databases, edb_id)
    if record is None:
        print(f"{edb_id} does not exist. Please double check that this is the correct id.")
        return 1

    src = record.full_path
    if not src.is_file():
        print(f"File not found on disk: {src}")
        return 1

    dest_dir = dest_dir or Path.cwd()
    dest = dest_dir / src.name
    shutil.copy2(src, dest)
    print(f"Copied to: {dest}")
    return 0


def examine(databases: Sequence[Database], edb_id: int) -> int:
    record = find_by_id(databases, edb_id)
    if record is None:
        print(f"{edb_id} does not exist. Please double check that this is the correct id.")
        return 1

    path = record.full_path
    print(f"[EDBID]: {record.edb_id}")
    print(f"[Exploit]: {record.title}")
    print(f"[Path]: {path}")
    print(f"[URL]: {record.www_url}")
    print(f"[Date]: {record.date}")
    print(f"[Author]: {record.author}")
    print(f"[Type]: {record.type}")
    print(f"[Platform]: {record.platform}")
    print(f"[Port]: {record.port}")
    if record.codes:
        print(f"[Codes]: {record.codes}")

    if not path.is_file():
        print(f"[!] File missing on disk: {path}")
        return 1

    if path.suffix.lower() == ".pdf":
        webbrowser.open(path.as_uri())
        return 0

    if sys.platform == "win32":
        # notepad for text; startfile for others
        try:
            if path.suffix.lower() in {".txt", ".py", ".rb", ".c", ".cpp", ".sh", ".pl", ".md", ".html"}:
                subprocess.Popen(["notepad", str(path)])
            else:
                os.startfile(str(path))  # type: ignore[attr-defined]
        except OSError as exc:
            print(f"[!] Could not open file: {exc}")
            return 1
    else:
        pager = os.environ.get("PAGER", "less")
        try:
            subprocess.call([pager, str(path)])
        except OSError:
            subprocess.call(["more", str(path)])
    return 0


def _git_default_branch(repo: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        branch = (result.stdout or "").strip()
        if branch and branch != "HEAD":
            return branch
    except OSError:
        pass
    # Prefer main, fall back to master
    for candidate in ("main", "master"):
        probe = subprocess.run(
            ["git", "-C", str(repo), "show-ref", "--verify", f"refs/remotes/origin/{candidate}"],
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0:
            return candidate
    return "main"


def update_databases(databases: Sequence[Database]) -> int:
    if shutil.which("git") is None:
        print("[!] git is not available on PATH. Install Git for Windows first.")
        return 1

    seen_paths = set()
    status = 0
    for database in databases:
        root = database.path
        key = str(root.resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)

        print(f"[i] Path: {root}")
        print(f"[i] Git Pulling: {database.name} ~ {root}")

        if not (root / ".git").exists():
            if database.git:
                print(f"[!] Not a git repo. Clone first:\n    git clone {database.git} \"{root}\"")
            else:
                print("[!] Not a git repo and no git URL configured.")
            status = 1
            continue

        branch = _git_default_branch(root)
        result = subprocess.run(
            ["git", "-C", str(root), "pull", "-v", "origin", branch],
            check=False,
        )
        if result.returncode != 0:
            status = result.returncode
        else:
            print("[i] Git Pull Complete")
    return status


def parse_nmap_xml(content: str) -> List[Tuple[str, str, List[str]]]:
    """Return list of (addr, hostname, terms) from nmap XML."""
    root = ET.fromstring(content)
    hosts_out: List[Tuple[str, str, List[str]]] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.attrib.get("addr", "")
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.attrib.get("name", "")
        terms: List[str] = []
        for service in host.findall("ports/port/service"):
            for key in ("name", "product", "version"):
                if key in service.attrib and service.attrib[key]:
                    terms.append(service.attrib[key])
        hosts_out.append((addr, hostname, terms))
    return hosts_out


def parse_nmap_grepable(content: str) -> List[Tuple[str, str, List[str]]]:
    """Return list of (addr, hostname, terms) from nmap -oG output."""
    if "Host: " not in content:
        return []
    hosts_out: List[Tuple[str, str, List[str]]] = []
    for line in content.splitlines():
        if "Host: " not in line or "Ports: " not in line:
            continue
        parts = line.split("\t")
        if not parts:
            continue
        host_part = parts[0][6:].split(" ", 1)
        addr = host_part[0]
        hostname = ""
        if len(host_part) > 1:
            hostname = host_part[1].strip("()")
        terms: List[str] = []
        ports_field = None
        for part in parts:
            if part.startswith("Ports: "):
                ports_field = part[7:]
                break
        if ports_field:
            for service in ports_field.split(", "):
                # port/state/proto/owner/service/sunrpc/... — take name-ish tokens
                chunks = service.replace("/", " ").split()
                if len(chunks) >= 5:
                    # typical: 80 open tcp http Apache httpd 2.4
                    terms.extend(chunks[4:])
        hosts_out.append((addr, hostname, terms))
    return hosts_out


def load_nmap_hosts(source) -> Optional[List[Tuple[str, str, List[str]]]]:
    """Load hosts/terms from a path, file object, or stdin-like content."""
    if hasattr(source, "read"):
        content = source.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
    else:
        path = Path(str(source))
        if not path.is_file():
            return None
        content = path.read_text(encoding="utf-8", errors="replace")

    content = content.strip()
    if not content:
        return None

    if content.startswith("<?xml"):
        try:
            return parse_nmap_xml(content)
        except ET.ParseError:
            return None

    grep = parse_nmap_grepable(content)
    return grep or None
