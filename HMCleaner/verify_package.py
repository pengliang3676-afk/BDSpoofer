"""Read-only package validation; no extraction and no device connection."""
import hashlib
import io
import pathlib
import plistlib
import struct
import sys
import tarfile

artifact = pathlib.Path(sys.argv[1])
package = artifact / 'HMCleaner_0.1.0_RootHide.deb'
blob = package.read_bytes()
digest = hashlib.sha256(blob).hexdigest()
expected = (artifact / 'SHA256SUMS.txt').read_text().split()[0]
assert digest == expected, 'Downloaded bytes differ from CI hash'
assert blob[:8] == b'!<arch>\n'
members = {}
position = 8
while position < len(blob):
    header = blob[position:position + 60]
    assert len(header) == 60 and header[-2:] == b'`\n'
    length = int(header[48:58])
    name = header[:16].decode('ascii').strip().rstrip('/')
    position += 60
    payload = blob[position:position + length]
    assert len(payload) == length
    if name.startswith('#1/'):
        extra = int(name[3:])
        name = payload[:extra].rstrip(b'\0').decode('ascii')
        payload = payload[extra:]
    members[name] = payload
    position += length + length % 2
assert members['debian-binary'] == b'2.0\n'
with tarfile.open(fileobj=io.BytesIO(members['control.tar.gz']), mode='r:gz') as tar:
    control = tar.extractfile('./control').read().decode()
    assert 'Architecture: iphoneos-arm64e' in control
    assert 'Package: com.codex.hmcleaner' in control
with tarfile.open(fileobj=io.BytesIO(members['data.tar.gz']), mode='r:gz') as tar:
    paths = tar.getnames()
    assert not any('/var/jb' in p or '..' in pathlib.PurePosixPath(p).parts for p in paths)
    assert all(not member.issym() and not member.islnk() for member in tar.getmembers())
    app = './Applications/HMCleaner.app/'
    info = plistlib.loads(tar.extractfile(app + 'Info.plist').read())
    assert info['CFBundleIdentifier'] == 'com.codex.hmcleaner'
    assert info['CFBundleShortVersionString'] == '0.1.0'
    assert info['MinimumOSVersion'] == '15.0'
    executable = tar.extractfile(app + 'HMCleaner').read()
    magic, count = struct.unpack_from('>II', executable)
    assert magic == 0xcafebabe and count == 2
    subtypes = set()
    for i in range(count):
        cpu, subtype, offset, size, align = struct.unpack_from('>IIIII', executable, 8 + 20 * i)
        assert cpu == 0x0100000c and offset + size <= len(executable)
        subtypes.add(subtype & 0x00ffffff)
        thin = executable[offset:offset + size]
        assert struct.unpack_from('<I', thin)[0] == 0xfeedfacf
        ncmds = struct.unpack_from('<I', thin, 16)[0]
        cursor = 32
        signed = False
        for _ in range(ncmds):
            cmd, length = struct.unpack_from('<II', thin, cursor)
            assert length >= 8 and cursor + length <= len(thin)
            if cmd == 0x1d:
                sig_offset, sig_size = struct.unpack_from('<II', thin, cursor + 8)
                assert sig_size > 0 and sig_offset + sig_size <= len(thin)
                signed = True
            cursor += length
        assert signed, 'Missing code signature data'
    assert subtypes == {0, 2}
print('PASS: CI hash, deb metadata, scoped payload, arm64 + arm64e, signature records')
print('SHA-256:', digest)
print('Signature validity itself is verified by codesign --verify --strict in CI.')
