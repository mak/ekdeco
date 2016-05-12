import argparse
import sys,re,os
import HTMLParser
import string,struct
from urllib import unquote
from lxml.etree import HTML


printset = set(string.printable)
isprintable = lambda yourstring: set(yourstring).issubset(printset)
chunks = lambda l, n: [l[x: x+n] for x in xrange(0, len(l), n)]
dehtml = lambda x: HTMLParser.HTMLParser().unescape(x)
HAS_INDEX = False

apr = argparse.ArgumentParser(description='Angler landing page decoder')
apr.add_argument('file',type=str, nargs='?', help='File path')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-o','--out',help="prefix for filename used to store decoded chunks")


def xor(x,y):
    r= []
    for i,c in enumerate(x):
        r.append(chr(ord(c)^ord(y[i%len(y)])))
    return ''.join(r)
ENC_DATA = {}
def get_keys(h):
    r = []
    for scr in h.xpath('//script/text()'):
        old_l = len(r)
        for st in re.findall("\s*('|\")([a-z0-9/+=]+)(\"|')\s*(;|\))",scr,re.I):
            
            if len(st[1]) < 6: continue
            try:
                #print st
                x=st[1]
                r.append(x)
            except:
                pass
        if len(r) > old_l:
            ## this is the same script with encoded data...
            ## there are three posibilites as seens so far,
            ### 1. separet variables
            ### 2. array initialized index by index
            ### 3. array initialized at once
            
            for enc in re.findall("([_a-z0-9]+(\[[0-9]+\])?\s*=\s*('|\")[-_. %a-z0-9/+=:]+(\"|')\s*)(,|;)",scr,re.I):
                ## this covers 1 and 2
                var,val = enc[0].split('=',1)
                var = var.strip()
                val = val.strip()[1:-1]
                #print `var`,`val`
                print '[+] found posible configuration var', var
                ENC_DATA[var]=val
            for enc in re.findall("var\s+([_a-z0-9]+)\s+=\s+\[((\s*('|\")[-_. %a-z0-9/+=:]+(\"|'),?)+)\s*\];",scr,re.I):
                ### this takes care of 3rd case
                var = enc[0]
                val = enc[1]
                sep = enc[-1] + ',' + enc[-1]
                print '[+] found configuration table', var

                for i,e in enumerate(val.split(sep)):
                    ENC_DATA[var+'[%d]'%i] = e.strip().strip(enc[-1])
            
                
#        print '-'*20
#        print scr
    return r


def xtea_decrypt_block(key,block,n=32,endian="<"):
    v0,v1 = struct.unpack(endian+"2L",block)
    k = struct.unpack(endian+"4L",key)
    delta,mask = 0x9e3779b9L,0xffffffffL
    sum = (delta * n) & mask
    for round in range(n):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
    return struct.pack(endian+"2L",v0,v1)
def xtea_worker(f,data):
    _len = len(data)
    assert len(data)% 8 == 0
    return ''.join(map(f,chunks(data,8)))

def xtea_decrypt(data,xkey):
    return xtea_worker(lambda c:xtea_decrypt_block(xkey,c),data)


def shuffle(data,key):
    key = [ key.index(c) for c in sorted(key) ]
    ks = len(key)
    data += ' ' * (ks - len(data)%ks)
    r = []
    for ch in chunks(data,ks):
        r.append(''.join([ ch[key[i]] for i in range(len(ch))]))
    return ''.join(r).strip()


def method_0(text,key):
    txt = re.sub(r'\s+|\.','',text)
    txt = txt.decode('base64')
    txt = xor(txt,key.decode('base64'))
    return txt

def method_1(text,key):
    txt = re.sub(r'\s+','%',text)
    txt = unquote(txt)
    txt = xtea_decrypt(txt,key[:16])
#@    print `txt`
    return txt

def method_2(text,key):
    txt = dehtml(text.replace(u"\xa0",' '))
    txt = shuffle(txt,key)
   # print txt
    return txt

def method_3(text,key):
    key = key.decode('hex')
    text = text.decode('hex')
    return xor(text,key)

def method_4(text,key):
    text = re.sub(r"(:+|=|\]\[)",'%',text.replace("\r\n",''))
    text = re.sub('%[A-F0-9]{2}',lambda g: g.group(0)[1:].decode('hex'),text)
    text = xtea_decrypt(text,key[:16])
    return text


DEOBF_METHODS = sorted(filter(lambda x:x.startswith('method_'),globals()))
def decode_page(t,k):
#    print globals()
    tlen = len(t)
    epsi = tlen /2
    for f in DEOBF_METHODS:
        f = globals()[f]
        try:
            x=f(t,k)
            #print len(t),len(x)
            ## there are some constant names in
            ## angler payload lets look for them
            if 'cryptKey' in x:
                return x
            elif 'getKolaio' in x:
                return x
            elif 'xTrue' in x and 'xFalse' in x:
                return x
            
            ## some basic heuristic....
            # if tlen - len(x) < epsi:
            #     print 'fop'
            #     return x
        except:
            pass
    return None

def get_num(x):
    return int(re.search('[0-9]+$',x).group(0))

        
if __name__ == '__main__':
    args = apr.parse_args()
    h = HTML(open(args.file).read().replace('<br>',''))
    key_var = None
    for key in get_keys(h):
        print '[*] testing key:',key
        stream = ''; txt = None
        for el in  h.xpath('//*[@id or @ui or @di]'):
            if el.text:
                txt = decode_page(el.text,key)
#            print txt  
            if not txt:
                continue

            if 'cryptKey' in txt:

                key_var = re.findall('var cryptKey = ([_a-z0-9]+(\[\s*[0-9]+\s*\])?),',txt,re.I)[0][0]
                key_var = re.sub('\s+','',key_var)
                print '[+] found key_var',key_var
                #txt = method_3(stream,key)
                #print txt
            if args.out:
                uid = el.attrib.get('id',None)
                uid = uid or el.attrib.get('di',None)
                uid = uid or el.attrib.get('ui',None)
                fname = os.path.join(args.dir,'.'.join([args.out,uid,'js']))
                print '[*] saving decoded chunk to',fname
                with open(fname,'w') as f: f.write(txt)
                
        if key_var: break
                #print txt
              

    if not key_var or key_var not in ENC_DATA:
        print '[-] err cant find key variable'
        sys.exit(1)

    print '[+] decoding using %s as key' % ENC_DATA[key_var]

    #ENC_DATA[key_var] = ENC_DATA[key_var].decode('base64')
    for k in ENC_DATA:
        if k == key_var: continue
        if not key_var.startswith(k[:2]) and \
           not key_var[1:].startswith(k[1:3]):
          continue

        v = ENC_DATA[k]
        data=shuffle(v,ENC_DATA[key_var])
        try:
            data_b= unquote(data).decode('base64')
        except:
            data_b = None

        if data_b and isprintable(data_b):
            data = data_b
        print '[+] decoded data:', data

                            

        ## this looks strange and needs more testing...
        # elif el.attrib.get('value',None):
        #     if not re.match('^[0-9a-f]+$',key,re.I):
        #         break
        #     val = el.attrib['value']
        #     ns = stream+val
        #     if len(ns)%2:
        #         stream = ns
        #         continue
            
        #     tmp = method_3(ns,key)    
        #     if not isprintable(tmp):
        #         txt = method_3(stream,key)
        #         stream = val
        #     else:
        #         txt = ''
        #         stream =ns
