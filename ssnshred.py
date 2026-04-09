#!/usr/bin/env python3
"""
ssnshred.py — Redact SSNs (and other sensitive numbers) from PDFs and text files.

Creates a redacted copy of the file; the original is never modified.

Requirements:
    Python >= 3.9
    PyMuPDF >= 1.24.0  (install: pip install pymupdf)

Usage:
    python ssnshred.py <file> <number> [<number> ...]
    python ssnshred.py <file> --auto
    python ssnshred.py <file> <number> --dry-run

Examples:
    python ssnshred.py return.pdf 123-45-6789 987-65-4321
    python ssnshred.py return.pdf --auto
    python ssnshred.py return.pdf 123456789 --dry-run

Flags:
    --auto      Auto-detect SSN-shaped patterns (XXX-XX-XXXX) and redact them.
    --dry-run   Show what would be redacted without writing a file.
"""

import argparse
import re
import sys
from pathlib import Path


def digits_only(s: str) -> str:
    """Strip a string down to its digits."""
    return re.sub(r"\D", "", s)


def ssn_variants(raw: str) -> list[str]:
    """Given a number (any format), return all common SSN format variants."""
    d = digits_only(raw)
    if len(d) != 9:
        return [raw]  # not SSN-length — search as-is
    return [
        f"{d[0:3]}-{d[3:5]}-{d[5:9]}",  # 123-45-6789
        f"{d[0:3]} {d[3:5]} {d[5:9]}",   # 123 45 6789
        d,                                 # 123456789
    ]


AUTO_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def build_search_terms(numbers: list[str], auto: bool) -> list[str]:
    """Build the full list of literal strings to search for."""
    terms: list[str] = []
    for n in numbers:
        terms.extend(ssn_variants(n))
    # deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for t in terms:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


# ── PDF redaction ───────────────────────────────────────────────────────────

def redact_pdf(src: Path, dest: Path, terms: list[str], auto: bool, dry_run: bool) -> int:
    try:
        import fitz  # PyMuPDF
    except ImportError:
        print("Error: PyMuPDF is required for PDF files. Install it with:\n"
              "  pip install pymupdf", file=sys.stderr)
        sys.exit(1)

    doc = fitz.open(src)
    total = 0

    for page_num, page in enumerate(doc, start=1):
        page_hits = 0

        # search for explicit terms
        for term in terms:
            rects = page.search_for(term)
            for rect in rects:
                if dry_run:
                    print(f"  Page {page_num}: found '{term}' at {rect}")
                else:
                    page.add_redact_annot(rect, text="REDACTED", fill=(1, 1, 1))
                page_hits += 1

        # auto-detect SSN patterns
        if auto:
            text = page.get_text()
            for match in AUTO_SSN_PATTERN.finditer(text):
                matched = match.group()
                # skip if already covered by explicit terms
                if matched in terms:
                    continue
                rects = page.search_for(matched)
                for rect in rects:
                    if dry_run:
                        print(f"  Page {page_num}: auto-detected '{matched}' at {rect}")
                    else:
                        page.add_redact_annot(rect, text="REDACTED", fill=(1, 1, 1))
                    page_hits += 1

        if not dry_run and page_hits > 0:
            page.apply_redactions()

        total += page_hits

    if not dry_run:
        doc.save(dest)
    doc.close()
    return total


# ── Text redaction ──────────────────────────────────────────────────────────

def redact_text(src: Path, dest: Path, terms: list[str], auto: bool, dry_run: bool) -> int:
    content = src.read_text(encoding="utf-8")
    total = 0

    for term in terms:
        count = content.count(term)
        if count and dry_run:
            print(f"  Found '{term}' — {count} occurrence(s)")
        total += count
        content = content.replace(term, "REDACTED")

    if auto:
        def _auto_replace(m: re.Match) -> str:
            nonlocal total
            if m.group() not in terms:
                if dry_run:
                    print(f"  Auto-detected '{m.group()}'")
                total += 1
                return "REDACTED"
            return m.group()
        content = AUTO_SSN_PATTERN.sub(_auto_replace, content)

    if not dry_run:
        dest.write_text(content, encoding="utf-8")
    return total


# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact SSNs and sensitive numbers from PDFs and text files."
    )
    parser.add_argument("file", type=Path, help="Path to the file to redact.")
    parser.add_argument("numbers", nargs="*", help="Numbers to redact (any format).")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-detect SSN patterns (XXX-XX-XXXX).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be redacted without writing a file.")
    args = parser.parse_args()

    src = args.file.expanduser().resolve()
    if not src.is_file():
        print(f"Error: '{src}' not found.", file=sys.stderr)
        sys.exit(1)

    if not args.numbers and not args.auto:
        print("Error: provide at least one number to redact, or use --auto.", file=sys.stderr)
        sys.exit(1)

    terms = build_search_terms(args.numbers, args.auto)
    dest = src.with_stem(src.stem + ".redacted")

    is_pdf = src.suffix.lower() == ".pdf"

    if args.dry_run:
        print(f"Dry run — scanning '{src.name}':")

    if is_pdf:
        count = redact_pdf(src, dest, terms, args.auto, args.dry_run)
    else:
        count = redact_text(src, dest, terms, args.auto, args.dry_run)

    if args.dry_run:
        print(f"\n{count} match(es) found. No file written.")
    elif count:
        print(f"Redacted {count} match(es). Output: {dest}")
    else:
        print("No matches found. No file written.")


if __name__ == "__main__":
    main()
