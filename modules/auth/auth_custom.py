import os
import logging
import requests
import json
import hashlib
import urllib.parse

cache = {}

n8n_dir = "/home/node/.n8n"
is_initialized_file = os.path.join(n8n_dir, "is_initialized")
is_initialized = False  # Initialize to False
if os.path.exists(is_initialized_file):
    with open(is_initialized_file, 'r') as f:
        content = f.read().strip()
        is_initialized = content.lower() == "true"

owner_email = "admin@local.com"


def generate_password(username):
    hashed_username = hashlib.sha256(username.encode()).hexdigest()
    password = hashed_username[:14]  # Truncate the hash to the desired length
    return "PWaa" + password + "!4;3"


def setup_n8n_owner(email, first_name, last_name):
    url = 'http://n8n:5678/rest/owner/setup'
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
    }
    data = {
        'email': email,
        'firstName': first_name,
        'lastName': last_name,
        'password': generate_password(email)
    }

    logging.info(data)
    response = requests.post(url, headers=headers, data=json.dumps(data))
    response.raise_for_status()


def n8n_get_admin_cookie():
    if owner_email not in cache:
        cache[owner_email] = n8n_login(owner_email)
    return cache[owner_email]["Set-Cookie"]


def n8n_invite_user(email):
    logging.info(f"Invitin user {email}")
    url = 'http://n8n:5678/rest/invitations'
    headers = {'Accept': 'application/json, text/plain, */*',
               'Content-Type': 'application/json',
               'Cookie': n8n_get_admin_cookie()}

    data = [{"email": email, "role": "global:member"}]
    response = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info(f"Invitation result {response.status_code}: {response.content}")
    response.raise_for_status()


def n8n_find_user(email):
    logging.info(f"Finding user {email}")
    url = 'http://n8n:5678/rest/users'
    headers = {'Accept': 'application/json, text/plain, */*',
               'Content-Type': 'application/json',
               'Cookie': n8n_get_admin_cookie()}

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    filtered_data = [p for p in response.json().get("data", []) if p.get("email") == email]
    first_match = filtered_data[0] if filtered_data else None

    return first_match


def n8n_complete_survey(email):
    logging.info(f"Complete survey for user {email}")
    url = 'http://n8n:5678/rest/me/survey'
    headers = {'Accept': 'application/json, text/plain, */*',
               'Content-Type': 'application/json',
               'Cookie': n8n_get_admin_cookie()}

    data = {"version": "v4",
            "personalization_survey_submitted_at": "2025-01-27T16:45:25.017Z",
            "personalization_survey_n8n_version": "1.75.2"}
    response = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info(f"Survey result {response.status_code}: {response.content}")
    response.raise_for_status()


def n8n_activate_user(email, activation_url):
    logging.info(f"Activating user {email} with url {activation_url}")

    parsed_url = urllib.parse.urlparse(activation_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    inviter_id = query_params.get('inviterId', [None])[0]  # .get returns a list, even for single values
    invitee_id = query_params.get('inviteeId', [None])[0]

    logging.info(f"Inviter ID: {inviter_id}")
    logging.info(f"Invitee ID: {invitee_id}")

    url = f'http://n8n:5678/rest/invitations/{invitee_id}/accept'
    headers = {'Accept': 'application/json, text/plain, */*',
               'Content-Type': 'application/json'}

    name_part = email.split('@')[0]
    first_name = name_part.split('.')[0].capitalize()
    last_name = name_part.split('.')[1].capitalize()

    data = {"firstName": first_name,
            "lastName": last_name,
            "password": generate_password(email),
            "inviterId": inviter_id}

    logging.info(f"Data {data}")
    response = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info(f"Result {response.status_code}: {response.content}")

    response.raise_for_status()


def n8n_login(email):
    logging.info(f"Logging in {email}")
    url = 'http://n8n:5678/rest/login'
    headers = {'Accept': 'application/json, text/plain, */*', 'Content-Type': 'application/json'}
    data = {'email': email, 'password': generate_password(email)}

    response = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info(f"Result {response.status_code}: {response.headers}")
    response.raise_for_status()
    return response.headers


def set_initialized():
    global is_initialized
    os.makedirs(n8n_dir, exist_ok=True)  # Create the directory if it doesn't exist
    with open(is_initialized_file, 'w') as f:
        f.write("True")
    is_initialized = True
    logging.info("n8n initialized.")


def initialize_n8n():
    logging.info("Initializing n8n.")
    first_name = "System"
    last_name = "Admin"
    setup_n8n_owner(owner_email, first_name, last_name)
    set_initialized()


def process_token(response, token, userinfo):
    """
    This is default implementation of token check.
    You can just drop your own implementation and replace this
    file. Don't forget to send response and body of some sort.
    At this point token is validated and decoded.
    """

    if not is_initialized:
        initialize_n8n()

    response.send_response(200)
    response.send_header("Content-type", "text/javascript")
    email = userinfo["email"]

    if email in cache:
        logging.debug(f"User found cached {email}")
        headers = cache[email]
    else:
        logging.info(f"User not cached {email}")
        user = n8n_find_user(email)
        logging.info(f"User found: {user}")
        if user is None:
            n8n_invite_user(email)
            user = n8n_find_user(email)

        if "isPending" in user and user["isPending"]:
            logging.info("User activation is pending!")
            n8n_activate_user(email, user["inviteAcceptUrl"].split("/")[3])
            user = n8n_find_user(email)

        headers = n8n_login(email)
        cache[email] = headers

        if "personalizationAnswers" not in user or user["personalizationAnswers"] is None:
            n8n_complete_survey(email)

    for key, value in headers.items():
        if key == 'Set-Cookie':
            logging.debug(f"Adding header {key}: {value}")
            response.send_header("Cookie", value)

    response.end_headers()
    response.wfile.write("{\"hello\":\"world\"}".encode())
