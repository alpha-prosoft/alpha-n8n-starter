from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from urllib.parse import urlparse, parse_qs

import jwt
import requests
import os
import json

from jwt import ExpiredSignatureError

import auth_custom
from http.cookies import SimpleCookie
import urllib.parse

cache = {}
jwks_client = None
auth_holder = 'X-Amzn-Oidc-Accesstoken'
auth_path = '/tr.auth/authorize'
auth_endpoint = None
token_endpoint = ''
oidc_scopes = "openid profile email"
oidc_client_id = None
oidc_client_secret = None

# ENV VARIABLES
http_proxy_key = "https_proxy"
oidc_well_known_uri_key = "oidc_well_known"
userinfo_uri_key = "userinfo_uri"
auth_holder_key = "auth_holder"
auth_path_key = 'auth_path'
oidc_scopes_key = 'oidc_scopes'
oidc_client_id_key = 'oidc_client_id'
oidc_client_secret_key = 'oidc_client_secret'


def get_env(env_key):
    logging.info(f'Fetching env: {env_key}')
    if env_key in os.environ:
        logging.info(f"Found {env_key} config")
        return os.environ[env_key]
    if env_key.upper() in os.environ:
        logging.info(f"Found {env_key.upper()} config")
        return os.environ[env_key.upper()]
    return None


def get_proxies():
    http_proxy = get_env(http_proxy_key)
    if http_proxy_key in os.environ:
        return {"https": os.environ[http_proxy_key]}
    return {}


def init_data():
    logging.info('Loading config')
    global jwks_client
    global auth_holder
    global auth_endpoint
    global token_endpoint
    global auth_path
    global oidc_scopes
    global oidc_client_id
    global oidc_client_secret

    oidc_well_known_uri = get_env(oidc_well_known_uri_key)
    logging.info(f"Initializing handler with {oidc_well_known_uri}")
    if oidc_well_known_uri is None:
        raise Exception('''JWKS_URI environment variable is mandatory.
                           For example on AWS Cognito it should
                           be: https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json''')

    if get_env(auth_holder_key):
        auth_holder = get_env(auth_holder_key)

    if get_env(oidc_client_id_key):
        oidc_client_id = get_env(oidc_client_id_key)
    if oidc_client_id is None:
        raise Exception(f"Oidc client is is mandatory env variable: {oidc_client_id_key}")

    if get_env(oidc_client_secret_key) is not None:
        oidc_client_secret = get_env(oidc_client_secret_key)
    if oidc_client_secret is None:
        raise Exception(f"Oidc client is is mandatory env variable: {oidc_client_secret_key}")

    if get_env(auth_path_key) is not None:
        auth_path = get_env(auth_path_key)

    if get_env(oidc_scopes_key) is not None:
        oidc_scopes = get_env(oidc_scopes_key)

    r = requests.get(oidc_well_known_uri, proxies=get_proxies()).json()
    jwks_uri = r["jwks_uri"]
    auth_endpoint = r["authorization_endpoint"]
    token_endpoint = r["token_endpoint"]
    logging.info(f"Got JWKS: {jwks_uri}")
    jwks_client = jwt.PyJWKClient(jwks_uri)


class S(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def get_token(self):
        # Try to get the token from headers
        token = self.headers.get(auth_holder)
        if token:
            logging.debug("Token found in headers")
            return token

        # Try to get the token from cookies
        if 'Cookie' in self.headers:
            cookie = SimpleCookie()
            cookie.load(self.headers['Cookie'])
            if auth_holder in cookie:
                token = cookie[auth_holder].value
                logging.debug("Token found in cookies")
                return token

        logging.warning("Token not found in headers or cookies")
        return None

    def send_error_message(self, message):
        logging.info("Sending error message")
        self.send_response(500)
        self.send_header('Error', message)
        self.end_headers()
        self.wfile.write("".encode())

    def send_redirect_login(self):
        logging.info("Redirecting to login")
        host = self.headers.get('X-Forwarded-Host')
        proto = self.headers.get('X-Forwarded-Proto')
        uri = self.headers.get('X-Forwarded-Uri')
        redirect_url = f"{proto}://{host}{auth_path}"

        auth_request = (f'response_type=code' +
                        f'&client_id={oidc_client_id}' +
                        f'&redirect_uri={urllib.parse.quote_plus(redirect_url)}' +
                        f'&state={urllib.parse.quote_plus(f"{proto}://{host}{uri}")}'
                        f'&scope={urllib.parse.quote_plus(oidc_scopes)}')

        self.send_response(302)
        self.send_header('Location', f"{auth_endpoint}?{auth_request}")
        self.end_headers()
        self.wfile.write("".encode())

    def respond(self):
        if jwks_client is None:
            self.send_error_message("System not initialized")
            return
        logging.debug("Processing login")

        token = self.get_token()
        if token is None:
            logging.info("No token. Redirecting to auth!")
            self.send_redirect_login()
            return

        userinfo = {}
        if token not in cache:
            public_key = jwks_client.get_signing_key_from_jwt(token)
            try:
                user_data = jwt.decode(token.encode(), public_key, audience=oidc_client_id, algorithms=["RS256"])
            except ExpiredSignatureError:
                self.send_redirect_login()
                return

            logging.info(token)
            userinfo_uri = get_env(userinfo_uri_key)
            if userinfo_uri is not None:
                logging.info("Fetching userinfo")
                headers = {'Authorization': 'Bearer ' + token}
                r = requests.get(userinfo_uri, headers=headers, proxies=get_proxies())
                userinfo = r.json()
                if "error" not in userinfo:
                    cache[token] = userinfo
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(json.dumps(userinfo).encode())
                    return
            else:
                logging.info("No userinfo so taking token data")
                cache[token] = user_data

        user = cache[token]
        auth_custom.process_token(self, token, user)

    def resolve_code(self, code_value, state):
        host = self.headers.get('Host')
        proto = 'http'
        redirect_url = f"{proto}://{host}{auth_path}"
        logging.info(f"Resolve code for endpoint: {token_endpoint}")
        auth_request = (f'grant_type=authorization_code' +
                        f'&client_id={oidc_client_id}' +
                        f'&client_secret={oidc_client_secret}' +
                        f'&redirect_uri={urllib.parse.quote_plus(redirect_url)}' +
                        f'&code={code_value}'
                        f'&scope={urllib.parse.quote_plus(oidc_scopes)}')

        logging.info(auth_request)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        r = requests.post(token_endpoint, headers=headers, data=auth_request)
        r.raise_for_status()

        self.send_response(302)
        self.send_header('Set-Cookie',
                         f'{auth_holder}={r.json()['id_token']}; Path=/; HttpOnly')  # Set cookie attributes
        self.send_header('Location', state)
        self.end_headers()
        self.wfile.write(b'You are logged in now! :)')

    def do_GET(self):
        uri = self.headers.get('X-Forwarded-Uri')
        logging.info(f"URI: {uri} or {self.path}")

        if self.path.startswith(f'{auth_path}?'):
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)

            logging.info(query_params)
            if 'code' in query_params:
                code_value = query_params['code'][0]
                self.resolve_code(code_value, query_params['state'][0])
            else:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'You dont belong here this way! :)')

        else:
            self.respond()

    def do_HEAD(self):
        self.respond()

    def do_PUT(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def do_DELETE(self):
        self.respond()

    def do_OPTIONS(self):
        self.respond()


def run(server_class=HTTPServer, handler_class=S, port=8081):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    logging.info("Initializing handler")
    init_data()

    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
