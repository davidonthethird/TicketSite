import requests

# Base URL of the Flask API
BASE_URL = "http://127.0.0.1:5000"

# Step 1: Login to get the JWT access token
login_url = f"{BASE_URL}/api/login"
login_data = {
    "username": "david",
    "password": "12345"
}

response = requests.post(login_url, json=login_data)

# Check if the request was successful
if response.status_code == 200:
    try:
        # Extract the access token from the response
        access_token = response.json().get("access_token")
        print("Access Token:", access_token)

        # Step 2: Use the token to access the user's bookings
        bookings_url = f"{BASE_URL}/api/user/bookings"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(bookings_url, headers=headers)

        # Check if the request to get bookings was successful
        if response.status_code == 200:
            try:
                # Print the user's bookings
                bookings = response.json()
                print("User Bookings:", bookings)
            except requests.exceptions.JSONDecodeError:
                print("Failed to parse JSON response for bookings:", response.text)
        else:
            print("Failed to retrieve bookings:", response.status_code, response.text)




    except requests.exceptions.JSONDecodeError:
        print("Failed to parse JSON response for login:", response.text)
else:
    print("Login failed:", response.status_code, response.text)
