import re
import sys
import zlib
import json
import hashlib
import argparse
import StringIO
from swf.movie import SWF
from Crypto.Cipher import ARC4

rc4_decrypt = lambda d,k : ARC4.new(k).decrypt(d)
apr = argparse.ArgumentParser(description='Neutrino swf decoder')
apr.add_argument('file',type=str, nargs='?', help='File path')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-e','--exploits',help='save exploits',default=False,action='store_true')
apr.add_argument('-i','--intermediate',help='save second swf',default=False,action='store_true')
apr.add_argument('-s','--second',help='second swf',default=False,action='store_true')

class Neutrino(SWF):


    @property
    def binary_data(self):
        if not hasattr(self,'_bd'):
            self._bd = self.build_dictionary()
        return self._bd


    @property
    def symbols(self):
        if not hasattr(self,'_sc'):
            for s in self.tags:
                if s.name == 'SymbolClass':
                    self._sc = s
                    break
        return self._sc.symbols

    @property
    def script(self):
        if not hasattr(self,'_s'):
            for s in self.tags:
                if s.name in ['DoABC','DoAction']:
                    self._s = s
                    break
        return self._s

    @property
    def strings(self):
        """get a list of strings from abcFile, whose length larger than 5
        """
        if not hasattr(self,'_ss'):
            self._ss = re.findall('[a-zA-Z0-9]{5,}', self.script.bytes)
        return self._ss

    def tag_by_name(self,name):
        for s in self.symbols:
            if s.name.endswith(name):
                return self.binary_data[s.tagId]
        return None

    def get_exploits(self):
        for sym in self.symbols:
            if not self.binary_data.has_key(sym.tagId):
                continue
            n = sym.name[:sym.name.find('$')]
            d = rc4_decrypt(self.binary_data[sym.tagId].data,self.ek_key)
            if d[:3] not in ['ZWS','CWS','FWS']:
                try:
                    d = zlib.decompress(d,-15)
                except Exception, e:
                    pass
            yield n, d

    def get_keys(self, cfg=None):
        the_cfg = cfg if cfg else self.get_cfg()
        data_id = [ s.tagId for s in self.symbols if 'html_rc4' in s.name ][0]
        for k in self.strings:
            if not hasattr(self, 'ek_key'):
                try:
                    d  = rc4_decrypt(self.binary_data[data_id].data,k)
                    d  = zlib.decompress(d,-15)
                    if '<htm' in d:
                        self.ek_key = k
                except Exception as e:
                    pass

            if not hasattr(self, 'cfg_key'):
                x  = rc4_decrypt(the_cfg,k)
                if x.startswith('{"'):
                    self.cfg_key = k

            if hasattr(self,'cfg_key') and hasattr(self,'ek_key'):
                break
            
        return hasattr(self, 'ek_key') and hasattr(self, 'cfg_key')

    def get_second_swf(self):

        def get_data(t):
            ''' in case we have some leftovers in resource names...'''
            try:
                return self.tag_by_name(t).data
            except:
                return ''
        #with open('/tmp/neu.swf','w') as f: f.write(s.script.bytes)
        if 'as$7:anonymous' in s.script.bytes:
            resources = []

            for i,g in enumerate(re.finditer('[a-zA-Z]+\.as\$[0-9]{1,2}:anonymous',s.script.bytes)):
                x=re.findall('[a-zA-Z0-9]{5,}',s.script.bytes[g.start()-40:g.start()])
                resources.append(x[0] if 'ByteArray' in x else x[-1])
        elif len(self.symbols) >= 3:
            strs = re.findall('[a-zA-Z0-9]{5,}',s.script.bytes)
            beg = strs.index('writeBytes')
            old = True
            try:
                end = strs.index('getDefinitionByName')
                old= False
            except:
                end = strs.index('Loader')
            resources = [strs[beg-1]] + strs[beg+1:end]
            if old and len(resources) < 5:
                ## this is older version with one letter-names...
                idx = self.script.bytes.index('writeBytes')
                h= re.findall('([a-z])\nwriteBytes((\x01[a-z])+)\x06Loader',self.script.bytes,re.M)[0]
                resources = [h[0]] + h[1].split("\x01")[1:]

            swf_bytes = ''.join([ get_data(r) for r in resources])

            for k in [self.binary_data[k].data for k in self.binary_data if len(self.binary_data[k].data) < 0x50]:
                d = rc4_decrypt(swf_bytes,k)
                if d[:3] in ['ZWS','CWS','FWS']:
                    return d
        elif len(self.symbols) == 2 and ('setPixel32' in self.strings or self.symbols[0].name == 'EmbedFile'):
            # new version(2b19b310887bb1beac421843671e5541f2e369b2815fcc3dc4dfdfc71e059a0d) only has two symbols:
            # [<SWFSymbol {'tagId': 1, 'name': 'EmbedFile'}>, <SWFSymbol {'tagId': 0, 'name': 'Main'}>]
            ### beter use funcion name which is using to set some bitmap, that is used to store payload
            ## see 7cb253e6997cf06e33eb8d0c74da9e10
            
            for k in self.strings:
                try:
                    d = rc4_decrypt(self.binary_data[1].data, k)
                    if d[:3] in ['ZWS','CWS','FWS']:
                        return d
                except Exception, e:
                    pass
        else:
            return None

    def get_cfg(self):
        for i in self.binary_data:
            x=self.binary_data[i].data[:3]
            try:
                return self.binary_data[i].data[3:int('0x'+x,16)+3]
            except:
                pass


if __name__ == '__main__':
    args = apr.parse_args()
    s = Neutrino(open(args.file))
    cfg_r = s.get_cfg()

    if not args.second:
        swf = s.get_second_swf()

        if not swf: sys.exit("[-] can't extract second swf, bailing")
        h = hashlib.sha256(swf).hexdigest()
        sys.stderr.write('[+] embeded swf (SHA256: %s) extracted'%h)
        if args.intermediate:
            p = '%s/%s.swf' % (args.dir,h)
            with open(p,'w') as f: f.write(swf)
            sys.stderr.write(',and saved to %s\n' % p)
        else:
            sys.stderr.write('\n')

        s2 = Neutrino(StringIO.StringIO(swf))
    else:
        s2 = s

    if not s2.get_keys(cfg_r):
        print >> sys.stderr,'[-] failed to get keys'
        exit(-1)

    if not cfg_r:
        cfg_r = s2.get_cfg()    # get config from 2nd layer swf
    print >> sys.stderr,'[+] cfg key: %s, exploit key: %s' % (s2.cfg_key,s2.ek_key)
    cfg = json.loads(rc4_decrypt(cfg_r,s2.cfg_key))
    import pprint
    pprint.pprint(cfg)
    if args.exploits:
        for n, ek in s2.get_exploits():
            h = hashlib.sha256(ek).hexdigest()
            p = '%s/%s_%s.ek.bin' % (args.dir,n,h)
            with open(p,'w') as f: f.write(ek)
            print >> sys.stderr, '[+] Exploit saved to %s' %p
