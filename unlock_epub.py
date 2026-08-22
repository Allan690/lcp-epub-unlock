#!/usr/bin/env python3
"""Remove Readium LCP DRM from EPUB files you legitimately own."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from contextlib import closing
from pathlib import Path
from xml.etree import ElementTree as ET

from Crypto.Cipher import AES

from lcp_crypto import decrypt_lcp_data, find_user_key, maybe_inflate


def decrypt_epub(inpath: Path, outpath: Path, passphrase: str, license_file: Path | None = None) -> None:
    with closing(zipfile.ZipFile(inpath, "r")) as zin:
        # Handle external license file if provided
        if license_file:
            if not license_file.is_file():
                raise ValueError(f"License file not found: {license_file}")
            license_data = json.loads(license_file.read_text())
        else:
            if "META-INF/license.lcpl" not in zin.namelist():
                raise ValueError("Not an LCP-protected EPUB (missing META-INF/license.lcpl)")
            license_data = json.loads(zin.read("META-INF/license.lcpl"))

        if "META-INF/encryption.xml" not in zin.namelist():
            raise ValueError("Not an LCP-protected EPUB (missing META-INF/encryption.xml)")
        profile = license_data["encryption"]["profile"]
        print(f"Profile: {profile}")

        user_key = find_user_key(license_data, passphrase)
        content_key = decrypt_lcp_data(license_data["encryption"]["content_key"]["encrypted_value"], user_key)
        print("Passphrase accepted")

        enc = ET.fromstring(zin.read("META-INF/encryption.xml"))
        ns = {"enc": "http://www.w3.org/2001/04/xmlenc#"}
        encrypted = {el.get("URI") for el in enc.findall(".//enc:CipherReference", ns) if el.get("URI")}

        outpath.parent.mkdir(parents=True, exist_ok=True)
        with closing(zipfile.ZipFile(outpath, "w")) as zout:
            mimetype = zipfile.ZipInfo("mimetype")
            mimetype.compress_type = zipfile.ZIP_STORED
            zout.writestr(mimetype, zin.read("mimetype"))

            for name in zin.namelist():
                if name in ("mimetype", "META-INF/encryption.xml", "META-INF/license.lcpl"):
                    continue
                data = zin.read(name)
                if name in encrypted:
                    iv, cipher = data[:16], data[16:]
                    # Skip decryption for resources that are too short
                    if len(data) < 16:
                        print(f"Resource {name} is too short to be encrypted (length {len(data)})", file=sys.stderr)
                    elif len(cipher) % 16 != 0:
                        print(
                            f"Resource {name} has invalid ciphertext length {len(cipher)} (not multiple of 16), skipping decryption", file=sys.stderr
                        )
                    else:
                        try:
                            data = AES.new(content_key, AES.MODE_CBC, iv).decrypt(cipher)
                            pad = data[-1] if isinstance(data[-1], int) else ord(data[-1])
                            if pad <= 16:  # Remove padding without minimum value check
                                data = data[:-pad]
                            # Skip inflation for PDF files to avoid padding errors
                            if not name.lower().endswith(".pdf"):
                                data = maybe_inflate(data)
                        except Exception as e:
                            print(f"Failed to decrypt {name}: {e}", file=sys.stderr)
                zout.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED)

    print(f"Wrote {outpath}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remove Readium LCP protection from an EPUB using your passphrase.")
    parser.add_argument("input", type=Path, help="LCP-protected EPUB file")
    parser.add_argument(
        "-p",
        "--passphrase",
        required=True,
        help="Your LCP passphrase (Reading Key from the ebook vendor)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output EPUB path (default: <input-stem> (unlocked).epub)",
    )
    parser.add_argument(
        "-l",
        "--license-file",
        type=Path,
        help="Path to external license file (if not embedded in EPUB)",
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1

    output = args.output or args.input.with_name(f"{args.input.stem} (unlocked).epub")

    try:
        decrypt_epub(args.input, output, args.passphrase, args.license_file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
