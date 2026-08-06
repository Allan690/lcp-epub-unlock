# lcp-epub-unlock

Remove [Readium LCP](https://readium.org/lcp-specs/) DRM from EPUB files you legitimately purchased, so you can read them on any standard EPUB reader.

Supports LCP encryption profiles **basic**, **1.0**, and **2.0–2.9** (including ebooks.com and similar vendors).

## Requirements

- Python 3.10+
- `pycryptodome`

## Install

```bash
git clone https://github.com/Allan690/lcp-epub-unlock.git
cd lcp-epub-unlock
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python unlock_epub.py "book.epub" --passphrase YOUR_READING_KEY
```

Write to a specific output path:

```bash
python unlock_epub.py "book.epub" -p YOUR_READING_KEY -o "book-unlocked.epub"
```

The tool:

1. Reads your LCP passphrase and derives the user key for the book's encryption profile
2. Decrypts all protected resources inside the EPUB
3. Writes a clean EPUB without `encryption.xml` or `license.lcpl`

## Where to find your passphrase

For ebooks.com purchases, the **Reading Key** / **LCP Passphrase** is in your account dashboard. Other vendors include a hint inside the license file or their support pages.

## Legal note

Only use this on ebooks you have legally purchased or borrowed and are entitled to read. You must supply your own valid LCP passphrase; this tool does not crack DRM.

## Credits

LCP profile 2.x key-derivation logic adapted from [lcpdf_exporter](https://github.com/Chaiavi/lcpdf_exporter) by Chaiavi (MIT License).
