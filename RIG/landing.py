import ast
import pprint
import hashlib
import argparse
import sys,re,os
import itertools

apr = argparse.ArgumentParser(description='RIG landing page decoder')
apr.add_argument('file',type=str, nargs='?', help='File path')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-o','--out',help="prefix for filename used to store decoded chunks")
args = None

def clear_comments(d):
    return re.sub('/\*[^/]*\*/','',d).replace('"+"','')

def decode_fdata(data):
    alphabet = 'za1sd0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[5:]
    mixtbl   = 'za1sdLMNOPWXY3defghiQRSTUVjklmnABC012DEFopq456789abcrstuvwxyzGHIJKZ'[5:]
    r=''.join([ alphabet[mixtbl.index(c)] for c in data ]).decode('hex').strip('\x00')
    x = ord(r[1])^ord(';')
    r = ''.join(chr(ord(c)^x)  for c in r)
    return r.strip("\x00")

def write_payload(t,payload):
    if args and args.out:
        h = hashlib.sha256(payload).hexdigest()
        with open(args.dir + os.sep + '.'.join([args.out,h,t]),'w') as f:
            f.write(payload)

def extract_from_swfpage(d):
    r ={}
    data = d.split('"')
    r['flash_url'] = data[-6]
    r['flash_drop_1'] = data[-4]
    r['drop_key'] = data[-2]
    return r

            
def do_rige(d):
    r = {'vb_drops':[]}
    for s in re.findall('<script>(.+?)</script>',d,re.S):
#        if not s: continue
        
        d = clear_comments(s)
	xxx = re.findall('"([/A-Za-z0-9=+]+)"\.replace\((/|"|\')([^/"\']+)("|/|\')',d)
	if xxx:
            basep,_,g,_= xxx[0]
        else:
	    ## last month changes...
	    basep = re.findall('"([/A-Za-z0-9=+]{65,})";',d)[0]
	    g= ''
        payload = clear_comments(basep.replace(g,'').decode('base64'))
        if 'Dim' in payload:
            x='http'+re.findall('"http(.*?)"',payload)[0]
            r['vb_drops'].append(x)
            t= 'exploit.vbs'
        elif 'application/x-shockwave-flash' in payload:
            d=payload.split(';')[-2].split('"')
            flash_url = d[1]
            r['flash_url'] = flash_url
	    try:
                id,key,url = decode_fdata(d[-2]).split(';')		        
	        r['flash_drop_%s'%id] = url
                r['drop_key'] = key
            except:
                r.update(extract_from_swfpage(payload))
            t = 'flash_drop.html'
        else:
            t = 'exploit.js'
    
        write_payload(t,payload)
        r['type'] = 'rig-e'
    return r

def do_rigv(d):
    r = {'vb_drops':[]}
    ## this gonna be fun...
    for s in re.findall('<script>(.+?)</script>',d,re.S):

        vars = re.findall('="([^"]+)".split\((\'|")([^\'"]+)(\'|")',s)
        repl  = re.findall('="(.+)";for',s)[0]
        x = []
        for v,_,e,_ in vars:
            x.append(v.split(e))
        payload=''.join( a + b for a,b in zip(x[1],itertools.cycle(x[0][::-1])))
        for i in range(0,len(repl)-4,2):
            payload = payload.replace(repl[i],repl[i+1])
            
        x=re.findall('var [a-z]+ = ([^;,]+)(;|,)',payload)[0][0]
        payload=ast.literal_eval(''.join(x.split("'+'"))).decode('base64')
        if 'redim' in payload.lower():
            x='http'+re.findall('"http(.*?)"',payload)[0]
            r['vb_drops'].append(x)
            t= 'exploit.vbs'
        
        elif 'application/x-shockwave-flash' in payload:
            r.update(extract_from_swfpage(payload))
            t = 'flash_drop.html'

        else:
            t = 'exploit.js'
            
        write_payload(t,payload)
        r['type'] = 'rig-v'
            
    return r

def doit(d):
    try:
        r = do_rige(d)
    except Exception as e:
	print `e`
        r=do_rigv(d)
    return r

if __name__ == '__main__':
    args = apr.parse_args()
    with open(sys.argv[1]) as f:
        d = f.read()
    r = doit(d)
    pprint.pprint(r)
    

        
