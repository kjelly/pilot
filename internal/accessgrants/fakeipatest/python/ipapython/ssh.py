"""Model of FreeIPA 4.13.4 ipapython/ssh.py SSHPublicKey (see ../README.txt).

Only what `normalize_sshpubkey` uses: parse a key given as a raw blob, a bare
base64 blob or an OpenSSH line with or without options, then openssh().
"""
import base64
import re
import struct

_BASE = re.compile(r'^[\t ]*(?P<keytype>[^\x00\n\r]+?) [\t ]*(?P<key>[^\x00\n\r]+?)'
                   r'(?:[\t ]+(?P<comment>[^\x00\n\r]*?)[\t ]*)?$')
_OPTION = re.compile(r'(?P<name>[-0-9A-Za-z]+)(?:="(?P<value>(?:\\"|[^\x00\n\r"])*)")?')
_MULTIPLE = ('permitopen', 'permitlisten')


class SSHPublicKey:
    def __init__(self, key):
        if not isinstance(key, str):
            raise TypeError("argument must be str")
        self._key = self._keytype = self._comment = None
        self._options = {}
        if not (self._parse_base64(key) or self._parse_openssh(key)):
            raise ValueError("not a valid SSH public key")

    def _parse_raw(self, blob):
        try:
            (length,) = struct.unpack('>I', blob[:4])
        except struct.error:
            return False
        if length < 1 or length > len(blob) - 4:
            return False
        try:
            keytype = blob[4:length + 4].decode('ascii')
        except UnicodeDecodeError:
            return False
        self._key, self._keytype, self._options, self._comment = blob, keytype, {}, None
        return True

    def _parse_base64(self, text):
        try:
            blob = base64.b64decode(text)
        except (TypeError, ValueError):
            return False
        return self._parse_raw(blob)

    def _parse_without_options(self, text):
        match = _BASE.match(text)
        if not match or not self._parse_base64(match.group('key')):
            return False
        if self._keytype != match.group('keytype'):
            return False
        self._comment = match.group('comment')
        return True

    def _parse_with_options(self, text):
        text = text.lstrip('\t ')
        options = {}
        while True:
            match = _OPTION.match(text)
            if not match:
                return False
            name, value = match.group('name').lower(), match.group('value')
            if value:
                value = value.replace('\\"', '"')
            if name in _MULTIPLE:
                options.setdefault(name, []).append(value)
            else:
                options[name] = value
            text = text[len(match.group(0)):]
            separator, text = text[:1], text[1:]
            if separator != ',':
                break
        if not self._parse_without_options(text):
            return False
        self._options = options
        return True

    def _parse_openssh(self, text):
        return self._parse_without_options(text) or self._parse_with_options(text)

    def openssh(self):
        out = '%s %s' % (self._keytype, base64.b64encode(self._key).decode('ascii'))
        if self._options:
            parts = []
            for name in sorted(self._options):
                value = self._options[name]
                if value is None:
                    parts.append(name)
                    continue
                for item in (value if isinstance(value, list) else [value]):
                    parts.append('%s="%s"' % (name, item.replace('"', '\\"')))
            out = '%s %s' % (','.join(parts), out)
        if self._comment:
            out = '%s %s' % (out, self._comment)
        return out
