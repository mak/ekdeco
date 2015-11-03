import re
import sys
import string
import argparse
from lxml.etree import HTML

printset = set(string.printable)
isprintable = lambda yourstring: set(yourstring).issubset(printset)

apr = argparse.ArgumentParser(description='Angler landing page decoder')
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
def decode_payload(offsets,p):
    for off in offsets:
       try:
         r = p[off:].decode('base64')
         if isprintable(r):
            return r
       except Exception as e:
         pass

if __name__ == '__main__':
    args = apr.parse_args()
    h = HTML(open(args.file).read())
    off = get_off(h)
    for el in h.xpath('//*[@id]'):
        if el.text:
            txt = decode_payload(off,el.text)
            if args.out:
                fname = os.path.join(args.dir,'.'.join([args.out,uid,'js']))
                print '[*] saving decoded chunk to',fname
                with open(fname,'w') as f: f.write(txt)
    
