"""CSV-backed Exploit-DB search using the standard csv module."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence

from searchsploit.config import Database

# Columns present in modern Exploit-DB CSV headers
TITLE_KEYS = ("description", "title")
FILE_KEYS = ("file", "path")
ID_KEYS = ("id", "edb_id", "edb-id")
DATE_KEYS = ("date_published", "date", "date_added")
AUTHOR_KEYS = ("author",)
TYPE_KEYS = ("type",)
PLATFORM_KEYS = ("platform",)
PORT_KEYS = ("port",)
CODES_KEYS = ("codes", "cve")


@dataclass
class ExploitRecord:
    edb_id: str
    file: str
    title: str
    date: str = ""
    author: str = ""
    type: str = ""
    platform: str = ""
    port: str = ""
    codes: str = ""
    db_path: Path = Path(".")
    db_name: str = ""

    @property
    def full_path(self) -> Path:
        return (self.db_path / self.file).resolve()

    @property
    def www_url(self) -> str:
        # file looks like exploits/windows/local/39446.py
        category = self.file.split("/")[0] if "/" in self.file or "\\" in self.file else "exploits"
        category = category.replace("\\", "/")
        top = category.split("/")[0]
        # Map CSV top-level folders to exploit-db.com URL segments
        mapping = {
            "exploits": "exploits",
            "shellcodes": "shellcode",
            "papers": "papers",
        }
        segment = mapping.get(top, "exploits")
        return f"https://www.exploit-db.com/{segment}/{self.edb_id}"


def _get_field(row: dict, keys: Sequence[str], default: str = "") -> str:
    for key in keys:
        if key in row and row[key] is not None:
            return str(row[key]).strip()
    # Case-insensitive fallback
    lower = {k.lower(): v for k, v in row.items()}
    for key in keys:
        if key.lower() in lower and lower[key.lower()] is not None:
            return str(lower[key.lower()]).strip()
    return default


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def iter_records(database: Database) -> Iterator[ExploitRecord]:
    with database.csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if not row:
                continue
            edb_id = _get_field(row, ID_KEYS)
            file_path = _get_field(row, FILE_KEYS)
            title = _strip_quotes(_get_field(row, TITLE_KEYS))
            if not edb_id or not file_path:
                continue
            yield ExploitRecord(
                edb_id=edb_id,
                file=file_path.replace("\\", "/"),
                title=title,
                date=_get_field(row, DATE_KEYS),
                author=_strip_quotes(_get_field(row, AUTHOR_KEYS)),
                type=_get_field(row, TYPE_KEYS),
                platform=_get_field(row, PLATFORM_KEYS),
                port=_get_field(row, PORT_KEYS),
                codes=_get_field(row, CODES_KEYS),
                db_path=database.path,
                db_name=database.name,
            )


def find_by_id(databases: Sequence[Database], edb_id: int | str) -> Optional[ExploitRecord]:
    needle = str(edb_id)
    for database in databases:
        for record in iter_records(database):
            if record.edb_id == needle:
                return record
    return None


_VERSION_RANGE_RE = re.compile(
    r"(?P<a>\d+(?:\.\d+)*)\s*(?:<=|<|=|>=|>)\s*(?P<b>\d+(?:\.\d+)*)"
)
_VERSION_TOKEN_RE = re.compile(r"\b\d+(?:\.\d+)+\b")


def _normalize(text: str, case_sensitive: bool) -> str:
    return text if case_sensitive else text.lower()


def _term_matches(
    haystack: str,
    term: str,
    *,
    case_sensitive: bool,
    strict: bool,
) -> bool:
    h = _normalize(haystack, case_sensitive)
    t = _normalize(term, case_sensitive)
    if t in h:
        return True
    if strict:
        return False
    # Fuzzy: allow a dotted version term to match a version range like 1.0 < 1.3
    if _VERSION_TOKEN_RE.fullmatch(term.strip()):
        for match in _VERSION_RANGE_RE.finditer(haystack):
            left = match.group("a")
            right = match.group("b")
            # Simple containment / ordering check on dotted versions as tuples
            try:
                term_v = tuple(int(x) for x in term.split("."))
                left_v = tuple(int(x) for x in left.split("."))
                right_v = tuple(int(x) for x in right.split("."))
            except ValueError:
                continue
            # Pad lengths
            maxlen = max(len(term_v), len(left_v), len(right_v))
            term_v = term_v + (0,) * (maxlen - len(term_v))
            left_v = left_v + (0,) * (maxlen - len(left_v))
            right_v = right_v + (0,) * (maxlen - len(right_v))
            if left_v <= term_v <= right_v or right_v <= term_v <= left_v:
                return True
    return False


def _excluded(text: str, excludes: Sequence[str], case_sensitive: bool) -> bool:
    hay = _normalize(text, case_sensitive)
    for ex in excludes:
        if not ex:
            continue
        if _normalize(ex, case_sensitive) in hay:
            return True
    return False


def search(
    databases: Sequence[Database],
    terms: Sequence[str],
    *,
    case_sensitive: bool = False,
    exact: bool = False,
    title_only: bool = False,
    strict: bool = False,
    excludes: Optional[Sequence[str]] = None,
    cve: Optional[str] = None,
) -> List[ExploitRecord]:
    """Return records matching all terms (AND) across configured databases."""
    excludes = list(excludes or [])
    working_terms = list(terms)

    if exact and working_terms:
        phrase = " ".join(working_terms)
        working_terms = [phrase]
        title_only = True

    results: List[ExploitRecord] = []
    cve_norm = None
    if cve:
        cve_norm = cve.upper().replace("CVE-", "").replace("CVE", "").strip("- ")
        if not cve_norm.startswith("CVE-"):
            # Accept both 2021-44228 and CVE-2021-44228
            if re.match(r"^\d{4}-\d+", cve_norm):
                cve_norm = f"CVE-{cve_norm}"
            else:
                cve_norm = cve.upper()

    for database in databases:
        for record in iter_records(database):
            blob_title = record.title
            blob_full = f"{record.title} {record.file}"
            search_blob = blob_title if (title_only or exact) else blob_full

            if _excluded(search_blob, excludes, case_sensitive):
                continue

            if cve_norm:
                codes = record.codes.upper()
                if cve_norm not in codes and cve_norm.replace("CVE-", "") not in codes:
                    continue

            if working_terms:
                ok = True
                for term in working_terms:
                    if not _term_matches(
                        search_blob,
                        term,
                        case_sensitive=case_sensitive,
                        strict=strict,
                    ):
                        ok = False
                        break
                if not ok:
                    continue

            results.append(record)

    return results


GENERIC_TERMS = {
    "microsoft",
    "microsoft windows",
    "apache",
    "ftp",
    "http",
    "linux",
    "net",
    "network",
    "oracle",
    "ssh",
    "ms-wbt-server",
}
DUD_TERMS = {"unknown", "none"}


def filter_terms(
    terms: Iterable[str],
    *,
    exact: bool = False,
    ignore_generic: bool = False,
    case_sensitive: bool = False,
    excludes: Optional[Sequence[str]] = None,
) -> List[str]:
    """Drop overly generic / duplicate terms unless --ignore is set."""
    terms_list = [t for t in terms if t]
    if exact:
        return terms_list

    excludes = [_normalize(x, case_sensitive) for x in (excludes or [])]
    cleaned: List[str] = []
    seen = set()
    for term in terms_list:
        low = term.lower()
        if low in DUD_TERMS:
            continue
        if low in GENERIC_TERMS and not ignore_generic:
            print(f"[-] Skipping term: {term} (too general; use -i to keep)")
            continue
        key = term if case_sensitive else low
        if key in seen:
            continue
        if any(ex and ex in _normalize(term, case_sensitive) for ex in excludes):
            continue
        seen.add(key)
        cleaned.append(term if case_sensitive else term.lower())

    return cleaned
