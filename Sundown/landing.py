import re
import sys
import hashlib
import argparse
from lxml.etree import HTML
from Crypto.Cipher import ARC4 as RC4

def decode_payloads(js):    
    funs = re.findall('function ([a-z]+)\(',js,re.I)
    data = key = None
    for f in funs:
        if data:
            key = re.findall(f + '\("([a-z0-9]+)",',js,re.I)
        else:
            data =re.findall(f + '\(\s*([a-z0-9]+)\s*\)\s*\)\s*;',js,re.I)
            data = re.findall('var\s+%s\s*=\s*"([a-zA-Z0-9+/=]+)";'%data[0],js)[0]

        if key and data:
            payload = RC4.new(key[0]).decrypt(data.decode('base64'))
            yield payload
            key = data = None
            
def decode_first(d):
    h = HTML(d)
    inner_js=''.join(h.xpath('//div/text()')).replace('_','')
    inner_js=inner_js.replace('&','').replace('%','')
    inner_js=inner_js.replace('=','').replace('undefined','')
    inner_js=inner_js.decode('hex')
    return inner_js

apr = argparse.ArgumentParser(description='Sundown landig page decoder')
apr.add_argument('file',type=str, nargs='?', help='File path')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-s','--save',help='save exploits',default=False,action='store_true')
args = None

def doit(d):
    if '<div' in d:
        d = decode_first(d)
        
    for p in decode_payloads(d):
        urls = []
        if 'application/x-shockwave-flash' in p:
            t = 'flash'
            x=p.strip().splitlines()[-2].replace("'",'"').split('"')
            url_b=x[1].split('/')[1]
            sh =x[-2].decode('hex').strip("\x00")
            urls = re.findall('"(/'+url_b+'.*?)"',p)
            payload_url = re.findall('(http.*)',sh)[0]
            
        elif 'data:application/x-silverlight' in p:
            t = 'silverlight'
            x = HTML(re.findall('"(.*?)"',p)[0])
            for i in x.xpath('//param'):
                if i.attrib['name'] == 'source':
                    urls = [i.attrib['value']]
                elif i.attrib['name'] == 'initParams':
                    vals = dict(map(lambda x: tuple(x.split('=')),i.attrib['value'].split('&')))
                    sh   = vals['shell32'].decode('hex').strip("\x00")
                    payload_url = re.findall('(http.*)',sh)[0]
                    
        elif 'CollectGarbage' in p:
            t = 'ie'
            x= p.strip().splitlines()[-1].replace("'",'"').split('"')
            payload_url = x[1] + ' rc4 key: %s' % x[-2]
            sh = re.findall('"([0-9a-f]+)"\+',p,re.I)[0].decode('hex')            
        else:
            t = 'unknown'

        sh_hash = hashlib.sha256(sh).hexdigest()
        print '[+] found %s exploit' % t
        if urls:
            print '[+] additional exploits:', ', '.join(urls)
        print '[+] payload url:', payload_url
        print '[+] shellcode hash:',sh_hash

        if args.save:
            n = args.dir + '/exp.%s.%s.txt' % (t,hashlib.sha256(p).hexdigest())
            with open(n,'w') as f:
                f.write(p)
            print '[+] js saved to', n
            if sh:
                n = args.dir + '/exp.%s.%s.sh.bin' % (t,sh_hash)
                with open(n,'w') as f:
                    f.write(sh)
                print '[+] shellcode saved to', n
            
#        print p
        

if __name__ == '__main__':
    args = apr.parse_args()
    with open(sys.argv[1]) as f:
        d = f.read()
    r = doit(d)
#    pprint.pprint(r)
