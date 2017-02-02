import re
import sys
import struct
from StringIO import StringIO
from swf.stream import SWFStream
from swf.movie import SWF, SWFHeader

from Crypto.Cipher import ARC4 as RC4
from Crypto.Cipher import AES


def get_keys(data):
    f = StringIO(data) if isinstance(data, basestring) else data
    ret = []
    for i in range(0, ord(f.read(1))):
        ret.append(f.read(16))
    return ret


class xSWF(SWF):

    class SS(SWFStream):

        def _read_bytes_aligned(self, bytes):
            buf = map(ord, self.f.read(bytes))
            return reduce(lambda x, y: x << 8 | y, buf, 0)

    @property
    def binary_data(self):
        if not hasattr(self, '_bd'):
            self._bd = self.build_dictionary()
        return self._bd

    @property
    def symbols(self):
        if not hasattr(self, '_sc'):
            for s in self.tags:
                if s.name == 'SymbolClass':
                    self._sc = s
                    break
        return self._sc.symbols

    @property
    def script(self):
        if not hasattr(self, '_s'):
            for s in self.tags:
                if s.name in ['DoABC', 'DoAction']:
                    self._s = s
                    break
        return self._s

    @property
    def strings(self, data=None):
        """get a list of strings from abcFile, whose length larger than 5
        """
        if not hasattr(self, '_ss'):
            self._ss = re.findall('[a-zA-Z0-9]{5,}', data or self.script.bytes)
        return self._ss

    def tag_by_name(self, name):
        for s in self.symbols:
            if s.name.endswith(name):
                return self.binary_data[s.tagId]
        return None

    # fix problem with pyswf...
    def parse(self, data):
        import io
        self._data = data = data if isinstance(
            data, SWFStream) else self.SS(data)
        self._header = SWFHeader(self._data)
        if self._header.compressed:
            temp = io.BytesIO()
            if self._header.compressed_zlib:
                import zlib
                data = data.f.read()
                zip = zlib.decompressobj()
                temp.write(zip.decompress(data))
            else:
                import pylzma
                data.readUI32()  # consume compressed length
                data = data.f.read()
                temp.write(pylzma.decompress(data))
            temp.seek(0)
            data = self.SS(temp)
        self._header._frame_size = data.readRECT()
        self._header._frame_rate = data.readFIXED8()
        self._header._frame_count = data.readUI16()
        self.parse_tags(data)


class RIG(xSWF):
    # assume
    # 1 - strings
    # 2 - key for string
    # 3 - shellcode
    # 4 - key for shellcode

    def read_blob(self, data):
        f = StringIO(data) if isinstance(data, basestring) else data
        cnt = struct.unpack('>I', f.read(4))[0]
        for i in range(cnt):
            size = struct.unpack('>I', f.read(4))[0]
            yield f.read(size)

    @property
    def type(self):
        if not hasattr(self, '_type'):
            self._type = 'rig-v' if len(rig.binary_data) == 2 else 'rig-e'
        return self._type

    @property
    def enc_strings(self):
        if not hasattr(self, 'rc4keys'):
            self.rc4keys = get_keys(self.binary_data[2].data)
        if not hasattr(self, '_enc_strings'):
            s = []
            for i, _s in enumerate(self.read_blob(self.binary_data[1].data)):
                s.append(RC4.new(self.rc4keys[i %
                                              len(self.rc4keys)]).decrypt(_s))
            self._enc_strings = s
        return self._enc_strings

    def get_clean_shellcode(self):
        if not hasattr(self, '_shellcode'):
            raise Exception('[-] decrypt it frist')
        if self._shellcode[9:13] != "\x49\x80\x34\x08":
            raise Exception('[-] Diffrent obfuscation your are on your own')

        xorb = ord(self._shellcode[13])
        size = struct.unpack('I', self._shellcode[5:9])[0]
        hdr = "\x90" * 0x19
        sh = ''.join(
            chr(ord(self._shellcode[0x19 + i]) ^ xorb) for i in range(size))
        rest = self._shellcode[0x19 + size:]
        self.shellcode = hdr + sh + rest

    @property
    def config(self):
        if self.type == 'rig-v':
            print '[-] for know i dont kwnow where config is'
            return None

        if not hasattr(self, '_cfgkeys'):
            self._cfgkeys = get_keys(self.binary_data[4].data)

        if not hasattr(self, '_config'):
            cfg = list(self.read_blob(self.binary_data[3].data))
            if len(cfg) == 1:
                print '[*] new version, only shelcode is here'
                self._config = None
                self._shellcode = RC4.new(
                    self._cfgkeys[0]).decrypt(cfg[0]).decode('hex')
                self.get_clean_shellcode()
            else:
                c = []
                for i, x in enumerate(cfg):
                    c.append(
                        unpad(AES.new(
                            self._cfgkeys[i % len(self._cfgkeys)]).decrypt(x)))
                self._config = c
        return self._config


def unpad(d):
    return d[:-ord(d[-1])]


if __name__ == '__main__':
    rig = xSWF(open(sys.argv[1]))
    data = rig.binary_data[1].data.decode('zlib')
    x = ord(data[1]) ^ ord('W')
    y = ord(data[2]) ^ ord('S')

    if x != y:
        print '[-] cant do it'
        sys.exit(-1)

    emb1 = 'CWS' + ''.join(map(lambda x: chr(ord(x) ^ y), data[3:]))
    with open('a.swf', 'w') as f:
        f.write(emb1)
    rig = xSWF(StringIO(emb1))
    data = rig.binary_data[31].data.decode('zlib')
    key = data[-16:]
    data = ''.join((chr(ord(c) ^ ord(key[i % 16]))
                    for i, c in enumerate(data[:-16].decode('base64'))))
    with open('b.swf', 'w') as f:
        f.write(data)
    rig = RIG(StringIO(data))

    print rig.type
    print rig.enc_strings
    if rig.config:
        print rig.config
        with open('s.bin', 'w') as f:
            f.write(rig._shellcode)
        with open('sc.bin', 'w') as f:
            f.write(rig.shellcode)
