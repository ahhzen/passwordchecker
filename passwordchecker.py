import requests
import hashlib

pwd_sha1 = ""
pwd_sha1_5 = ""

def request_api_data(query):
    url = "https://api.pwnedpasswords.com/range/" + query
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f"Error fetch : {res.status_code}, check again")
    else:
        return res

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    
    return sha1password


def read_response(response):
    print(type(response.text))
    print(response.text)


def get_password_count(response, head, tail):
    hashes = (line.split(":") for line in response.text.splitlines() )

    for h, count in hashes:
        if tail == h:
            return count

    return 0
##        print(h, count)

password = input("Enter a password to be checked : ")

pwd_sha1 = pwned_api_check(password)
pwd_sha1_5, tail = pwd_sha1[:5], pwd_sha1[5:]
response = request_api_data(pwd_sha1_5)

print(pwd_sha1_5, tail)
count = get_password_count(response, pwd_sha1_5, tail)

print(f"Password found : {count}")


