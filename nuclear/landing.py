import os
import re
import sys
import struct
import string
import argparse
from urllib import unquote

from lxml.etree import HTML

printset = set(string.printable)
isprintable = lambda yourstring: set(yourstring).issubset(printset)
xor = lambda xk,d : ''.join(map(lambda x: chr(ord(x)^xk),d))

apr = argparse.ArgumentParser(description='Nuclear landing page decoder')
apr.add_argument('file',type=str, nargs='?', help='File path')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-o','--out',help="prefix for filename used to store decoded chunks")


def get_off(h):
    r = []
    for el in h.xpath('//script'):
        for hit in re.finditer("('|\")>('|\")\s*\)\s*\+\s*([0-9]+)",el.text):
            try:
               r.append(int(hit.group(3))-1)
            except:
               pass
    return r
def decode64(p):
    for s in ['','=','==']:
       try:
         r = (p.replace('-','/').replace('_','+').replace('!','0')+s).decode('base64')
         return r
       except:
           pass
    return None


def decode_payload(offsets,p):
    for off in offsets:
        r = decode64(p[off:])
        if r and isprintable(r):
            return r
    return None

def decode_bin_payload(sh):
    sh = sh.decode('hex')
    if sh.startswith("\x60\xeb\x11\x58\xb9"):
        off = struct.unpack('I',sh[5:9])[0]+4
        xk = ord(sh[off+0x19+1]) ^ ord(';')
        if ord(sh[off+0x19])^xk in [0x32,0x31]:
            r=xor(xk,sh[off+0x19:]).split("\x00")[0].split(';')[:3]
            return r
    return None

def decode_shellcode(pay,r):
    for _line in pay.splitlines():
        try:
            data = _line.split('=')[1].strip().split(';')[0][1:-1]
            if re.match("^[0-9A-Fa-f]+$",data):
                id,key,url = decode_bin_payload(data)
                if id == '1':
                    typ = 'standalone'
                elif id == '2':
                    typ = 'service'
                r[0]={'sh-key':key,'sh-url':url,'type':typ}
                print '[+] %s binary from %s - with key:%s' % (typ,url,key)
                return True
        except Exception as e:
            pass
    return False

def analyze_payload(txt,args=None):
    enc = None
    ret  = {}
    for line in txt.splitlines():
        ext = None
        if line.startswith('var') and ("'" in line or '"' in line):
            try:
                if 'decodeBase64' in line:
                    line = line.replace('decodeBase64(','').replace(')','')

                name,pay = line.split('=',1)
                pay = pay.strip()[1:-2].decode('base64')
            except:
                continue
            
            if 'class' in pay or 'Randomize' in pay or 'end sub' in pay or 'Dim' in pay:
                print '[*] found vbs payload'
                ext = 'vbs'
                            
            elif 'catch' in pay:
                print '[*] found js payload'
                ext = 'js'
                r = [{}]
                if 'powMod' in pay and 'rc4' in pay and 'str2bigInt' in pay:
                    enc = 'DH+rc4'
                elif decode_shellcode(pay,r):
                    enc = 'xor'
                    ret.update(r[0])
                
        elif line.startswith('return') and re.match(r"^return\s+('|\")[A-Z0-9+/=]+(\"|');?$",line,re.I):
            data=line.split(' ',1)[1].lstrip(';')[1:-1].decode('base64')
            if data.startswith('http'):
                print '[+] payload-data',data

        elif line.startswith('flash_run'):
            data= line.lstrip(';')[11:-2].split(',')
            flsh_u = data[0][1:-1]
            param1 = decode64(data[1][1:-1])#.decode('base64')
            print 'flash-payload',flsh_u
            print 'p1 (%d)'%len(param1),`param1`

            if len(data) >2:
                param2 = unquote(data[2][1:-1]).decode('base64')
                ret['binary'] = param2
                print 'binary-url',param2
                
            ret['flash'] = flsh_u
                
        if ext and args and args.out:
            uid = name.split(' ')[1]
            fname = os.path.join(args.dir,'.'.join([args.out,'inner',uid,ext]))
            print '[*] saving decoded chunk to',fname
            with open(fname,'w') as f: f.write(pay)
    if enc:
        print '[*] payload delivery encryption:',enc
        ret['encryption']=enc
    return ret

def decode_first_js(data):
    h = HTML(data)
    off = get_off(h)
    off.append(0)
    for el in h.xpath('//*[@id]'):
        if el.text:
            txt = decode_payload(off,el.text)
            if not txt:
                continue
            yield txt

        
        
if __name__ == '__main__':
    args = apr.parse_args()
    for txt in decode_first_js(open(args.file).read()):
        if args.out:
            fname = os.path.join(args.dir,'.'.join([args.out,el.attrib['id'],'js']))
            print '[*] saving decoded chunk to',fname
            with open(fname,'w') as f: f.write(txt)
        analyze_payload(txt,args)
                
                        
