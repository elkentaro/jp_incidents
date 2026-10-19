"""Bounded PDF text extraction worker. Input: PDF bytes; output: UTF-8 text.

Run separately from the collector so malformed documents cannot hang a poll.
Image-only documents require OCR and intentionally return no text here.
"""
import io
import sys

MAX_BYTES = 12_000_000
MAX_PAGES = 40
MAX_TEXT = 20_000


def extract(raw):
    from pypdf import PdfReader

    if len(raw) > MAX_BYTES or not raw.lstrip().startswith(b"%PDF-"):
        raise ValueError("Invalid or oversized PDF")
    reader = PdfReader(io.BytesIO(raw), strict=False)
    if reader.is_encrypted and not reader.decrypt(""):
        raise ValueError("PDF requires a password")
    result = ""
    if len(reader.pages) > MAX_PAGES:
        print("JPI_PDF_TRUNCATED", file=sys.stderr)
    for page in reader.pages[:MAX_PAGES]:
        result += (page.extract_text() or "") + "\n"
        if len(result) >= MAX_TEXT:
            break
    return result[:MAX_TEXT].strip()


def main():
    # Unix limits complement the parent process's wall-clock timeout.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    except (ImportError, ValueError, OSError):
        pass
    try:
        result = extract(sys.stdin.buffer.read(MAX_BYTES + 1))
        sys.stdout.buffer.write(result.encode("utf-8"))
    except Exception as error:
        print(f"{type(error).__name__}: PDF extraction failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
