"""PDF text extraction worker. Runs in a child process with CPU, memory and file-size limits
(blueprint §19.3). Reads the PDF from stdin and writes one JSON object to stdout.

Only visible page text is extracted. Metadata, annotations, attachments and JavaScript are
never read. The child has no need for the network, and none of the code paths used here
open a connection.
"""

from __future__ import annotations

import io
import json
import resource
import sys

MAX_PAGES = 300
MAX_CHARS = 2_000_000


def main() -> int:
    mem = int(sys.argv[1]) * 1024 * 1024
    cpu = int(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    data = sys.stdin.buffer.read()
    from pypdf import PdfReader  # imported after limits are in force

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        print(json.dumps({"error": "encrypted"}))
        return 2
    pages = []
    total = 0
    for i, page in enumerate(reader.pages):
        if i >= MAX_PAGES:
            break
        text = page.extract_text() or ""
        total += len(text)
        pages.append(text)
        if total > MAX_CHARS:
            break
    print(json.dumps({"text": "\n\n".join(pages), "pages": len(reader.pages)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
