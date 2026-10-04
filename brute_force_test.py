import requests
import time


URL = "http://127.0.0.1:5000/"

USERNAME = "admin"

WRONG_PASSWORD = "WrongPassword123"


print("=" * 60)
print("BRUTE-FORCE LOGIN ATTEMPT SIMULATION")
print("=" * 60)

print(f"Target URL : {URL}")
print(f"Username   : {USERNAME}")
print("Attempts   : 7")
print("=" * 60)


for attempt in range(1, 8):

    print(f"\nAttempt {attempt}")

    data = {
        "username": USERNAME,
        "password": WRONG_PASSWORD
    }

    try:

        response = requests.post(
            URL,
            data=data,
            allow_redirects=True
        )

        page = response.text

        if "Account locked" in page:
            print("RESULT : ACCOUNT LOCKED")
            print("Brute-force protection activated.")
            break

        elif "Too many failed attempts" in page:
            print("RESULT : ACCOUNT LOCKED")
            break

        elif "Invalid password" in page:
            print("RESULT : LOGIN FAILED")

        else:
            print("RESULT : REQUEST COMPLETED")

    except requests.exceptions.ConnectionError:

        print("ERROR : Flask server is not running.")

        break

    time.sleep(1)


print("\n" + "=" * 60)
print("TEST COMPLETED")
print("=" * 60)