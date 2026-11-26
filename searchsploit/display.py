"""Terminal formatting helpers for SearchSploit output."""

from __future__ import annotations

import shutil
import sys
from typing import List, Sequence

from searchsploit.csvdb import ExploitRecord


def terminal_width(default: int = 80) -> int:
    try:
        return max(40, shutil.get_terminal_size(fallback=(default, 24)).columns)
    except OSError:
        return default


def init_color(enabled: bool) -> bool:
    """Enable ANSI colors on Windows when possible. Returns effective flag."""
    if not enabled:
        return False
    if sys.platform == "win32":
        try:
            import colorama

            colorama.init()
            return True
        except ImportError:
            print(
                "[!] colorama not installed; output without colour. "
                'Install with: pip install colorama'
            )
            return False
    return True


def highlight(text: str, terms: Sequence[str], colour: bool) -> str:
    if not colour or not terms:
        return text
    result = text
    # Apply longest terms first to reduce partial overlap weirdness
    for term in sorted(terms, key=len, reverse=True):
        if not term:
            continue
        lower = result.lower()
        needle = term.lower()
        marker = 0
        pieces: List[str] = []
        while True:
            idx = lower.find(needle, marker)
            if idx < 0:
                pieces.append(result[marker:])
                break
            pieces.append(result[marker:idx])
            pieces.append(f"\033[91m{result[idx:idx + len(term)]}\033[0m")
            marker = idx + len(term)
        result = "".join(pieces)
    return result


def draw_line(col: int, border_at: int | None = None) -> None:
    width = col
    if border_at is None:
        print("-" * max(1, width - 1))
        return
    lim = max(1, min(border_at, width - 3))
    left = "-" * lim
    right = "-" * max(0, width - lim - 2)
    print(f"{left}+{right}")


def print_row(
    col: int,
    lim: int,
    left: str,
    right: str,
    *,
    overflow: bool = False,
    colour: bool = True,
) -> None:
    if overflow:
        print(f"{left} | {right}")
        return

    left_len = lim - 1
    right_len = max(8, col - lim - 3)

    # Expand visible width budget for ANSI sequences
    def visible_pad(text: str, width: int) -> str:
        # Count ANSI escapes roughly
        raw = text
        budget = width
        i = 0
        visible = 0
        while i < len(raw) and visible < budget:
            if raw.startswith("\033[", i):
                end = raw.find("m", i)
                if end < 0:
                    break
                i = end + 1
                continue
            i += 1
            visible += 1
        # Slice preserving escapes up to visible budget
        sliced = raw[:i]
        # Pad with spaces for remaining visible columns
        pad = budget - visible
        if pad > 0:
            sliced += " " * pad
        return sliced

    if not colour:
        print(f"{left[:left_len]:<{left_len}.{left_len}s} | {right[:right_len]:<{right_len}.{right_len}s}")
        return

    print(f"{visible_pad(left, left_len)} | {visible_pad(right, right_len)}")


def print_results(
    records_by_name: dict[str, List[ExploitRecord]],
    terms: Sequence[str],
    *,
    colour: bool,
    overflow: bool,
    show_id: bool,
    show_www: bool,
    db_paths: dict[str, str],
) -> None:
    col = terminal_width()
    lim = int(col * 0.8) if show_id else (col - 3) // 2

    for name, records in records_by_name.items():
        if not records:
            print(f"{name}: No Results")
            continue

        header_lim = max(10, col // 4)
        draw_line(col, header_lim)
        print_row(col, header_lim, f"{name} Title", "Path", overflow=False, colour=False)
        print_row(
            col,
            header_lim,
            "",
            db_paths.get(name, ""),
            overflow=False,
            colour=False,
        )
        draw_line(col, header_lim)
        draw_line(col, lim)

        for record in records:
            title = highlight(record.title, terms, colour)
            if show_id:
                right = highlight(record.edb_id, terms, colour)
            elif show_www:
                right = highlight(record.www_url, terms, colour)
            else:
                right = highlight(record.file, terms, colour)
            print_row(col, lim, title, right, overflow=overflow, colour=colour)

        draw_line(col, lim)


def records_to_json(
    terms: Sequence[str],
    records_by_name: dict[str, List[ExploitRecord]],
    db_paths: dict[str, str],
) -> str:
    import json

    payload = {"SEARCH": " ".join(terms)}
    for name, records in records_by_name.items():
        key = name.upper()
        payload[f"DB_PATH_{key}"] = db_paths.get(name, "")
        payload[f"RESULTS_{key}"] = [
            {
                "Title": r.title,
                "EDB-ID": int(r.edb_id) if r.edb_id.isdigit() else r.edb_id,
                "Date": r.date,
                "Author": r.author,
                "Type": r.type,
                "Platform": r.platform,
                "Path": str(r.full_path).replace("\\", "/"),
            }
            for r in records
        ]
    return json.dumps(payload, indent=4, ensure_ascii=False)
