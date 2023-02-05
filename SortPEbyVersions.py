#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ExtractAndSortPEbyVersions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 05 Feb 2023


import argparse
import binascii
import os
import pefile
import requests
from rich import progress
import time
import shutil
import hashlib


def file_sha256sum(path_to_file):
    sha256_hash = hashlib.sha256()
    with open(path_to_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def pe_get_version(pathtopefile):
    data = {"FileVersion": "", "ProductVersion": ""}
    p = pefile.PE(pathtopefile)
    data["FileVersion"] = "%d.%d.%d.%d" % ((p.VS_FIXEDFILEINFO[0].FileVersionMS >> 16) & 0xffff, (p.VS_FIXEDFILEINFO[0].FileVersionMS >> 0) & 0xffff, (p.VS_FIXEDFILEINFO[0].FileVersionLS >> 16) & 0xffff, (p.VS_FIXEDFILEINFO[0].FileVersionLS >> 0) & 0xffff)
    data["ProductVersion"] = "%d.%d.%d.%d" % ((p.VS_FIXEDFILEINFO[0].ProductVersionMS >> 16) & 0xffff, (p.VS_FIXEDFILEINFO[0].ProductVersionMS >> 0) & 0xff, (p.VS_FIXEDFILEINFO[0].ProductVersionLS >> 16) & 0xffff, (p.VS_FIXEDFILEINFO[0].ProductVersionLS >> 0) & 0xffff)
    return data


def download_pdb(download_dir, pathtopefile):
    pdbname, guid, pdbage = get_pe_debug_infos(pathtopefile)
    download_url = "http://msdl.microsoft.com/download/symbols/%s/%s%X/%s" % (pdbname, guid.upper(), pdbage, pdbname)
    print("[>] Downloading %s" % download_url)
    r = requests.head(
        download_url,
        headers={"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"},
        allow_redirects=True
    )
    if r.status_code == 200:
        target_file = download_dir + os.path.sep + pdbname
        with progress.Progress() as p:
            progress_bar, csize = p.add_task("[cyan]Downloading %s" % pdbname, total=int(r.headers["Content-Length"])), 1024*16
            pdb = requests.get(r.url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.10036.206"}, stream=True)
            with open(target_file, "wb") as f:
                for chunk in pdb.iter_content(chunk_size=csize):
                    f.write(chunk)
                    p.update(progress_bar, advance=len(chunk))
    else:
        print("[!] (HTTP %d) Could not find %s " % (r.status_code, download_url))


def get_pe_debug_infos(pathtopefile):
    p = pefile.PE(pathtopefile, fast_load=False)
    pedata = {d.name: d for d in p.OPTIONAL_HEADER.DATA_DIRECTORY}
    raw_debug_data = [e for e in p.parse_debug_directory(pedata["IMAGE_DIRECTORY_ENTRY_DEBUG"].VirtualAddress, pedata["IMAGE_DIRECTORY_ENTRY_DEBUG"].Size) if e.entry is not None]
    raw_debug_data = raw_debug_data[0].entry

    guid = "%08X%04X%04X%s" % (
        raw_debug_data.Signature_Data1,
        raw_debug_data.Signature_Data2,
        raw_debug_data.Signature_Data3,
        binascii.hexlify(raw_debug_data.Signature_Data4).decode("utf-8").upper()
    )
    return raw_debug_data.PdbFileName.strip(b'\x00').decode("utf-8"), guid, raw_debug_data.Age


def parseArgs():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-s", "--source-dir", default=None, required=True, help='')
    parser.add_argument("-a", "--archive-dir", default=None, required=True, help='')
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    return parser.parse_args()


def process(path_to_file, versions, dump_dir, debug):
    try:
        pev = pe_get_version(path_to_file)
        filename = os.path.basename(path_to_file)
        sha256hash = file_sha256sum(path_to_file)

        if filename not in versions.keys():
            versions[filename] = {}

        if pev["FileVersion"] in versions[filename]:
            if versions[filename][pev["FileVersion"]]["sha256"] != sha256hash:
                print("[!] Hash mismatch for version %s" % pev["FileVersion"])
                print("  | A: %s" % versions[filename][pev["FileVersion"]]["path"])
                print("  | B: %s" % path_to_file)

        if pev["FileVersion"] not in versions[filename]:
            versions[filename][pev["FileVersion"]] = {
                "path": path_to_file,
                "sha256": sha256hash
            }
            final_dir = dump_dir + "/%s/%s/" % (filename, pev["FileVersion"])
            if not os.path.exists(final_dir):
                os.makedirs(final_dir, exist_ok=True)
            saved_filename = final_dir + os.path.sep + os.path.basename(filename)
            saved_filename = saved_filename.replace("//", "/")
            shutil.copyfile(path_to_file, saved_filename)

            print("[+] Found '%s' with version '%s'" % (filename, pev["FileVersion"]))
            if debug:
                print("[+] Saved file to %s" % saved_filename)

            download_pdb(download_dir=final_dir, pathtopefile=saved_filename)
    except pefile.PEFormatError as e:
        pass
    return versions


if __name__ == '__main__':
    options = parseArgs()
    extensions = [".dll", ".exe"]
    #
    versions = {}
    for root, dirs, files in os.walk(options.source_dir):
        for file in files:
            if any([file.lower().endswith(ext) for ext in extensions]):
                process(
                    path_to_file=os.path.join(root, file),
                    versions=versions,
                    dump_dir=options.archive_dir,
                    debug=options.verbose
                )
