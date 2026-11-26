"""SearchSploit command-line interface (Windows-native)."""

from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from typing import List, Optional

from searchsploit import __version__
from searchsploit import actions
from searchsploit import config
from searchsploit import csvdb
from searchsploit import display


HELP_EPILOG = """
=======
 Notes
=======
 * You can use any number of search terms.
 * Search terms are not case-sensitive (by default), and ordering is irrelevant.
   * Use '-c' for case-sensitive searching.
   * Use '-e' for an exact title match.
   * Use '-s' for strict matching (disable version-range fuzzy match).
 * Use '-t' to search titles only (exclude file path), reducing false positives.
 * When updating or displaying help, search terms are ignored.
 * Configure database paths in %USERPROFILE%\\.searchsploit_rc
   or run scripts\\install.ps1
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="searchsploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
==========
 Examples
==========
  searchsploit afd windows local
  searchsploit -t oracle windows
  searchsploit -p 39446
  searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
  searchsploit --cve 2021-44228
  searchsploit --nmap scan.xml

  Manual: https://www.exploit-db.com/searchsploit
""",
        epilog=HELP_EPILOG,
    )

    exclusive = parser.add_mutually_exclusive_group()

    parser.add_argument("searchTerms", nargs="*", help=argparse.SUPPRESS)

    parser.add_argument(
        "-c",
        "--case",
        action="store_true",
        help="Perform a case-sensitive search (Default is inSEnsITiVe).",
    )
    parser.add_argument(
        "-e",
        "--exact",
        action="store_true",
        help='Perform an EXACT match on exploit title (Default is AND) [Implies "-t"].',
    )
    parser.add_argument(
        "-i",
        "--ignore",
        action="store_true",
        help="Keep generic terms that are normally skipped.",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Show result in JSON format.",
    )
    exclusive.add_argument(
        "-m",
        "--mirror",
        type=int,
        metavar="EDB-ID",
        help="Mirror (copy) an exploit to the current working directory.",
    )
    parser.add_argument(
        "-o",
        "--overflow",
        action="store_true",
        help="Exploit titles are allowed to overflow their columns.",
    )
    exclusive.add_argument(
        "-p",
        "--path",
        type=int,
        metavar="EDB-ID",
        help="Show the full path to an exploit (and copy it to the clipboard).",
    )
    parser.add_argument(
        "-s",
        "--strict",
        action="store_true",
        help="Strict search; disable fuzzy matching for version ranges.",
    )
    parser.add_argument(
        "-t",
        "--title",
        action="store_true",
        help="Search JUST the exploit title (Default is title AND path).",
    )
    parser.add_argument(
        "-u",
        "--update",
        action="store_true",
        help="Check for and install exploitdb git updates.",
    )
    parser.add_argument(
        "-w",
        "--www",
        action="store_true",
        help="Show URLs to Exploit-DB.com rather than the local path.",
    )
    exclusive.add_argument(
        "-x",
        "--examine",
        type=int,
        metavar="EDB-ID",
        help="Examine (open) the exploit locally.",
    )
    parser.add_argument(
        "--colour",
        "--color",
        dest="colour",
        action="store_false",
        help="Disable colour highlighting in search results.",
    )
    parser.add_argument(
        "--id",
        action="store_true",
        help="Display the EDB-ID value rather than local path.",
    )
    parser.add_argument(
        "--cve",
        metavar="CVE",
        help="Search by CVE id (matches the CSV codes column), e.g. 2021-44228.",
    )
    parser.add_argument(
        "--nmap",
        metavar="file.xml",
        nargs="?",
        type=argparse.FileType("r", encoding="utf-8", errors="replace"),
        default=None,
        const=sys.stdin,
        help='Check services from Nmap XML (or -oG) output. Use with "-v" style terms if needed.',
    )
    parser.add_argument(
        "--exclude",
        default="",
        help='Remove values from results. Separate with "|" e.g. --exclude="PoC|/dos/".',
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _parse_excludes(raw: str) -> List[str]:
    if not raw:
        return []
    # Support official-style pipe separation and leftover nargs-style spaces
    parts: List[str] = []
    for chunk in raw.replace(",", "|").split("|"):
        chunk = chunk.strip().strip('"').strip("'")
        if chunk:
            parts.append(chunk)
    return parts


def _load_dbs_or_exit():
    try:
        databases = config.load_databases()
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return None
    if not databases:
        print(
            "ERROR: No Exploit-DB CSV databases found.\n"
            "Clone the official repo and point .searchsploit_rc at it:\n"
            "  git clone https://gitlab.com/exploit-database/exploitdb.git C:\\exploitdb\n"
            "Or run: .\\scripts\\install.ps1",
            file=sys.stderr,
        )
        return None
    return databases


def _group_results(records, databases):
    ordered = OrderedDict((db.name, []) for db in databases)
    for record in records:
        ordered.setdefault(record.db_name, []).append(record)
    db_paths = {db.name: str(db.path) for db in databases}
    return ordered, db_paths


def run_search(
    databases,
    terms: List[str],
    args: argparse.Namespace,
) -> int:
    excludes = _parse_excludes(args.exclude)
    if not args.case:
        excludes = [e.lower() for e in excludes]

    cleaned = csvdb.filter_terms(
        terms,
        exact=args.exact,
        ignore_generic=args.ignore,
        case_sensitive=args.case,
        excludes=excludes,
    )

    if not cleaned and not args.cve:
        print("No usable search terms. Provide terms, --cve, or -i for generic terms.")
        return 1

    records = csvdb.search(
        databases,
        cleaned,
        case_sensitive=args.case,
        exact=args.exact,
        title_only=args.title,
        strict=args.strict,
        excludes=excludes,
        cve=args.cve,
    )
    grouped, db_paths = _group_results(records, databases)

    colour = display.init_color(args.colour)

    if args.json:
        print(display.records_to_json(cleaned or terms, grouped, db_paths))
        return 0

    display.print_results(
        grouped,
        cleaned,
        colour=colour,
        overflow=args.overflow,
        show_id=args.id,
        show_www=args.www,
        db_paths=db_paths,
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not argv and sys.stdin.isatty():
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    # Update does not require existing CSVs (user may fix paths after),
    # but still needs RC. Fall back to listing unique paths from RC even if empty.
    if args.update:
        try:
            databases = config.load_databases()
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        if not databases:
            # Try to update paths referenced in RC even if CSV missing
            print("[!] No local CSV databases detected; nothing to update.")
            print("    Clone Exploit-DB first (see scripts\\install.ps1).")
            return 1
        return actions.update_databases(databases)

    databases = _load_dbs_or_exit()
    if databases is None:
        return 2

    if args.mirror is not None:
        return actions.mirror(databases, args.mirror)
    if args.path is not None:
        return actions.show_path(databases, args.path)
    if args.examine is not None:
        return actions.examine(databases, args.examine)

    # Nmap mode: search per host
    if args.nmap is not None:
        display.init_color(args.colour)
        hosts = actions.load_nmap_hosts(args.nmap)
        if not hosts:
            print("[!] Could not parse Nmap XML or grepable (-oG) input.")
            return 1
        status = 0
        for addr, hostname, host_terms in hosts:
            label = f"{addr}" + (f" ({hostname})" if hostname else "")
            print(f"Finding exploits for {label}")
            merged = list(host_terms) + list(args.searchTerms)
            print(f"Searching terms: {merged}")
            code = run_search(databases, merged, args)
            status = status or code
            print()
        return status

    terms = list(args.searchTerms)
    if not sys.stdin.isatty() and args.nmap is None:
        piped = sys.stdin.read().strip()
        if piped:
            terms.extend(piped.split())

    if not terms and not args.cve:
        parser.print_help()
        return 0

    return run_search(databases, terms, args)


if __name__ == "__main__":
    raise SystemExit(main())
