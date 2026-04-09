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


def build_search_terms(numbers: list[str]) -> list[str]:
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

def _replace_all(text: str, terms: list[str], replacement: str = "REDACTED") -> tuple[str, int]:
    """Replace all occurrences of any term in text. Returns (new_text, count)."""
    count = 0
    for term in terms:
        n = text.count(term)
        if n:
            text = text.replace(term, replacement)
            count += n
    return text, count


def _scrub_metadata(doc, terms: list[str], auto: bool, dry_run: bool) -> int:
    """Remove SSNs from the PDF metadata dictionary and XMP XML."""
    total = 0
    meta = doc.metadata
    dirty = False
    for key in ("title", "author", "subject", "keywords", "creator", "producer"):
        val = meta.get(key, "") or ""
        new_val, n = _replace_all(val, terms)
        if auto:
            new_val, n2 = AUTO_SSN_PATTERN.subn("REDACTED", new_val)
            n += n2
        if n:
            if dry_run:
                print(f"  Metadata[{key}]: found {n} match(es)")
            meta[key] = new_val
            dirty = True
            total += n
    if dirty and not dry_run:
        doc.set_metadata(meta)

    # XMP XML metadata
    xmp = doc.xref_xml_metadata()
    if xmp:
        new_xmp, n = _replace_all(xmp, terms)
        if auto:
            new_xmp, n2 = AUTO_SSN_PATTERN.subn("REDACTED", new_xmp)
            n += n2
        if n:
            if dry_run:
                print(f"  XMP metadata: found {n} match(es)")
            elif not dry_run:
                doc.set_xml_metadata(new_xmp)
            total += n

    return total


def _scrub_form_fields(doc, terms: list[str], auto: bool, dry_run: bool) -> int:
    """Remove SSNs from AcroForm widget values and regenerate appearances."""
    total = 0
    for page in doc:
        for widget in page.widgets():
            val = widget.field_value or ""
            new_val, n = _replace_all(val, terms)
            if auto:
                new_val, n2 = AUTO_SSN_PATTERN.subn("REDACTED", new_val)
                n += n2
            if n:
                if dry_run:
                    print(f"  Form field '{widget.field_name}': found {n} match(es)")
                else:
                    widget.field_value = new_val
                    widget.update()
                total += n
    return total


def _scrub_embedded_files(doc, terms: list[str], auto: bool, dry_run: bool) -> int:
    """Remove SSNs from embedded file attachments."""
    total = 0
    # Collect scrub operations first (we'll delete+re-add, which changes indices)
    scrubs: list[tuple[str, bytes, dict]] = []
    for i in range(doc.embfile_count()):
        try:
            data = doc.embfile_get(i)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue  # skip binary attachments
            new_text, n = _replace_all(text, terms)
            if auto:
                new_text, n2 = AUTO_SSN_PATTERN.subn("REDACTED", new_text)
                n += n2
            if n:
                info = doc.embfile_info(i)
                name = info.get("name", f"attachment-{i}")
                if dry_run:
                    print(f"  Embedded file '{name}': found {n} match(es)")
                else:
                    scrubs.append((name, new_text.encode("utf-8"), info))
                total += n
        except Exception:
            pass
    # Apply scrubs via delete + re-add (embfile_upd has a bug with raw bytes)
    for name, new_data, info in scrubs:
        doc.embfile_del(name)
        doc.embfile_add(name, new_data,
                        filename=info.get("filename", name),
                        ufilename=info.get("ufilename", name),
                        desc=info.get("description", ""))
    return total


def redact_pdf(src: Path, dest: Path, terms: list[str], auto: bool, dry_run: bool) -> int:
    try:
        import fitz  # PyMuPDF
    except ImportError:
        print("Error: PyMuPDF is required for PDF files. Install it with:\n"
              "  pip install pymupdf", file=sys.stderr)
        sys.exit(1)

    doc = fitz.open(src)
    total = 0

    # 1. Scrub metadata (title, keywords, XMP)
    total += _scrub_metadata(doc, terms, auto, dry_run)

    # 2. Scrub form field values (AcroForms / widgets)
    total += _scrub_form_fields(doc, terms, auto, dry_run)

    # 3. Scrub embedded file attachments
    total += _scrub_embedded_files(doc, terms, auto, dry_run)

    # 4. Redact visible page content
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

    # 5. Save with garbage collection to remove orphaned pre-redaction objects
    if not dry_run:
        doc.save(dest, garbage=4, deflate=True)
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

    terms = build_search_terms(args.numbers)
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
        if is_pdf:
            print("Scrubbed: page content, metadata, form fields, "
                  "embedded files. Saved with garbage collection.")
    else:
        print("No matches found. No file written.")


if __name__ == "__main__":
    main()
