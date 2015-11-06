import sys,os
import hashlib
#import requests
import urlparse
import argparse
###
sys.path.append(os.path.dirname(__file__))
import landing
import requesocks as requests


apr = argparse.ArgumentParser(description='Nuclear payload downloader')
apr.add_argument('url',type=str, nargs='?', help='fist url that is starting infection chain')
apr.add_argument('-d','--dir',help='Output dir',default='/tmp')
apr.add_argument('-o','--out',help="prefix for filename used to store decoded chunks")
args = apr.parse_args()


def xor(x,y):
    if len(x)>len(y):
        y = y * (len(x)/len(y))
    return ''.join(map(lambda x: chr(ord(x[0])^ord(x[1])),zip(x,y)))




UA = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'

hdrs = {}
#hdrs['Accept-Language']='pl'
hdrs['Accept']='image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/x-ms-application, application/x-ms-xbap, application/vnd.ms-xpsdocument, application/xaml+xml, */*'
hdrs['User-Agent'] = UA

s = requests.Session()
#s.proxies={'http':'http://localhost:8118','https':'http://localhost:8118'}

s.headers = hdrs

## lets do it...
BASE_URL = sys.argv[1]
r=s.get(BASE_URL)
if r.status_code == 444:
    print "[-] zed's dead, either blackisted ip or wrong country..."
    sys.exit(1)

url = urlparse.urlparse(r.url)
payload = {}
## decode landing
for txt in landing.decode_first_js(r.content):
    payload.update(landing.analyze_payload(txt))

if 'encryption' not in payload:
    print '[-] sorry, i cant deal with it...'
    sys.exit(1)

## this looks like a bug in nuclerear we dont need to
## be exploited to get payload...
if payload['encryption'] == 'xor':
    ## right now only xor is handled
    r = s.get(payload['sh-url'])
    if r.ok:
        data = xor(r.content,payload['sh-key'])
        h = hashlib.md5(data).hexdigest()
        if data[:2] == 'MZ':
            print '[+] hooray, we got our payload, saving to %s'
            with open(fname,'w') as f:
                f.write(data)
                
elif payload['encryption'] == 'DH+rc4':
    print '[-] not dh for now'
    sys.exit(1)
else:
    print '[-] imposible...'
