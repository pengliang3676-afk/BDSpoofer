#!/usr/bin/env python3
# Build a standard GNU ar archive (the format a .deb requires) without
# relying on the macOS BSD ar, which corrupts archives containing non-Mach-O
# members (debian-binary / control.tar.gz / data.tar.gz).
import sys
import os


def member_header(name, size, mtime=0, uid=0, gid=0, mode=0o100644):
    name_field = (name + "/").ljust(16)
    fields = (
        name_field.encode("ascii"),
        str(mtime).ljust(12).encode("ascii"),
        str(uid).ljust(6).encode("ascii"),
        str(gid).ljust(6).encode("ascii"),
        ("%o" % mode).ljust(8).encode("ascii"),
        str(size).ljust(10).encode("ascii"),
        b"`\n",
    )
    header = b"".join(fields)
    if len(header) != 60:
        raise SystemExit("ar member header must be 60 bytes, got %d" % len(header))
    return header


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: make_deb_ar.py output.deb member [member ...]")
    out = sys.argv[1]
    members = sys.argv[2:]
    with open(out, "wb") as archive:
        archive.write(b"!<arch>\n")
        for path in members:
            with open(path, "rb") as handle:
                data = handle.read()
            name = os.path.basename(path)
            archive.write(member_header(name, len(data)))
            archive.write(data)
            if len(data) % 2 == 1:
                archive.write(b"\n")


if __name__ == "__main__":
    main()
