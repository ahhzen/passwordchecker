import requests
import hashlib
import sys

pwd_sha1 = ""
pwd_sha1_5 = ""

def request_api_data(query):
    url = "https://api.pwnedpasswords.com/range/" + query
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f"Error fetch : {res.status_code}, check again")
    else:
        return res

def get_password_leak_count(response, tail):
    hashes = (line.split(":") for line in response.text.splitlines() )

    for h, count in hashes:
        if tail == h:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    head, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(head)
    leakcount = int(get_password_leak_count(response, tail))
    return leakcount


def main(argv):
    for password in argv:
        count = pwned_api_check(password)

        if count > 0:
            print(f"Your password '{password}' has been used {count} before")
        else:
            print(f"Your password '{password}' seems ok for now. Check again sometime later")

sys.exit(main(sys.argv[1:]))




