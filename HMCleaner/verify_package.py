"""Read-only validation for the HMCleaner 1.2.1 desktop App package."""
import hashlib
import io
import pathlib
import plistlib
import stat
import struct
import sys
import tarfile


artifact = pathlib.Path(sys.argv[1])
package = artifact / "HMCleaner_1.2.1_RootHide.deb"
blob = package.read_bytes()
digest = hashlib.sha256(blob).hexdigest()
hash_lines = (artifact / "SHA256SUMS.txt").read_text().splitlines()
expected = next(line.split()[0] for line in hash_lines if line.endswith(package.name))
assert digest == expected, "downloaded package differs from the recorded CI hash"
assert blob[:8] == b"!<arch>\n"

members = {}
position = 8
while position < len(blob):
    header = blob[position : position + 60]
    assert len(header) == 60 and header[-2:] == b"`\n"
    length = int(header[48:58])
    name = header[:16].decode("ascii").strip().rstrip("/")
    position += 60
    payload = blob[position : position + length]
    assert len(payload) == length
    if name.startswith("#1/"):
        extra = int(name[3:])
        name = payload[:extra].rstrip(b"\0").decode("ascii")
        payload = payload[extra:]
    members[name] = payload
    position += length + length % 2

assert members["debian-binary"] == b"2.0\n"
with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as tar:
    control = tar.extractfile("./control").read().decode()
    assert "Architecture: iphoneos-arm64e" in control
    assert "Package: com.peng.hmcleaner" in control
    assert "Version: 1.2.1" in control
    postinst = tar.extractfile("./postinst").read().decode()
    assert "chmod 4755 /usr/local/bin/hmcleaner" in postinst
    assert "chmod 4755 /Applications/HMCleaner.app/hmcleaner-helper" in postinst
    assert "uicache -a" in postinst


def verify_fat_macho(payload):
    magic, count = struct.unpack_from(">II", payload)
    assert magic == 0xCAFEBABE and count == 2
    subtypes = set()
    for index in range(count):
        cpu, subtype, offset, size, align = struct.unpack_from(">IIIII", payload, 8 + 20 * index)
        assert cpu == 0x0100000C and offset + size <= len(payload)
        subtypes.add(subtype & 0x00FFFFFF)
        thin = payload[offset : offset + size]
        assert struct.unpack_from("<I", thin)[0] == 0xFEEDFACF
        commands = struct.unpack_from("<I", thin, 16)[0]
        cursor = 32
        signed = False
        for _ in range(commands):
            command, length = struct.unpack_from("<II", thin, cursor)
            assert length >= 8 and cursor + length <= len(thin)
            if command == 0x1D:
                sig_offset, sig_size = struct.unpack_from("<II", thin, cursor + 8)
                assert sig_size > 0 and sig_offset + sig_size <= len(thin)
                signed = True
            cursor += length
        assert signed, "missing code signature data"
    assert subtypes == {0, 2}


with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r:gz") as tar:
    entries = {item.name: item for item in tar.getmembers()}
    assert not any("/var/jb" in name or ".." in pathlib.PurePosixPath(name).parts for name in entries)
    assert all(not item.issym() and not item.islnk() for item in entries.values())

    app = "./Applications/HMCleaner.app/"
    info = plistlib.loads(tar.extractfile(app + "Info.plist").read())
    assert info["CFBundleIdentifier"] == "com.peng.hmcleaner"
    assert info["CFBundleShortVersionString"] == "1.2.1"
    assert info["MinimumOSVersion"] == "15.0"
    app_binary = tar.extractfile(app + "HMCleaner").read()
    assert b"HMCLEANER_GUI_1_2_1" in app_binary
    verify_fat_macho(app_binary)

    app_helper_name = app + "hmcleaner-helper"
    app_helper = entries[app_helper_name]
    assert stat.S_IMODE(app_helper.mode) == 0o4755, oct(stat.S_IMODE(app_helper.mode))
    app_helper_binary = tar.extractfile(app_helper_name).read()
    assert b"HMCLEANER_GUI_1_2_1" not in app_helper_binary
    verify_fat_macho(app_helper_binary)

    helper_name = "./usr/local/bin/hmcleaner"
    helper = entries[helper_name]
    assert stat.S_IMODE(helper.mode) == 0o4755, oct(stat.S_IMODE(helper.mode))
    helper_binary = tar.extractfile(helper_name).read()
    assert helper_binary == app_helper_binary
    assert b"HMCLEANER_GUI_1_2_1" not in helper_binary
    verify_fat_macho(helper_binary)

print("PASS: package metadata, desktop App, setuid helper, arm64 + arm64e and signatures")
print("SHA-256:", digest)
