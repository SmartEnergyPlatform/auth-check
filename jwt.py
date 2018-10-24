"""
   Copyright 2018 InfAI (CC SES)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import BaseHTTPServer
import requests 
import json 
import urllib
import os 

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers['Content-Type'] != "application/json":
            self.send_response(400)
            self.end_headers()
        else:
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            print("Payload: " + json.dumps(payload))
            headers = payload.get("headers")
            params = payload.get("uri_args")
            path = headers.get("target_uri")
            method = headers.get("target_method")
            token = None
            authorization_header = headers.get("authorization")
            print(authorization_header)
            if not authorization_header:
                if isinstance(params, dict):
                    authorization_header = params.get("token")
                    print(authorization_header)

            if method == "OPTIONS":
                print("OPTIONS request is allowed")
                # TODO: check in middleman if user id ist da 
                # sollte eigentlich nicht mit gesendet werden
                payload = json.dumps({"userID": ""})
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(payload)
            else:
                if authorization_header:
                    token = authorization_header.split(" ")[-1]
                
                    result_authentication, error_authentication = self.check_authentication(token)

                    if result_authentication:
                        print("authentication was successfull")
                        result_authorization = self.check_user_authorization(result_authentication, payload)
                        if result_authorization:
                            result_client_authorization = self.check_client_authorization(result_authentication)
                            print("authorization was successfull")
                            payload = json.dumps({"userID": result_authentication.get("sub")})
                            self.send_response(200)
                            self.send_header("Content-type", "application/json")
                            self.end_headers()
                            self.wfile.write(payload)
                        else: 
                            self.send_response(401)
                            self.end_headers()
                            self.wfile.write("user is not authorized")
                    else:
                        self.send_response(401)
                        self.end_headers()
                        self.wfile.write(error_authentication)
                else:
                    print("missing access token -> unauthorized")
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write("missing access token")
                self.wfile.close()

    def check_authentication(self, token):
        data = {
            "client_id": os.environ["client_id"],
            "client_secret": os.environ["client_secret"],
            "token": token,
            "token_type_hint": "access_token"
        }

        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            keycloak_url = "{url}/auth/realms/master/protocol/openid-connect/token/introspect".format(url=os.environ["keycloak_url"])
            print("send token validation request to: " + keycloak_url)
            response = requests.post(keycloak_url, data=data, headers=headers,verify=False).json()
            print("token validation response: " + json.dumps(response))
            if response.get("active"):
                print("access token is valid")
                return (response, None)
            else:
                print("access token is not valid")
                error_message = response.get("error_description")
                print(error_message)
                if error_message:
                    print(error_message)
                    return (False, error_message)
                else:
                    return (False, "access Token is not valid")
        except Exception as e:
            print(e)
            return (False, "Access Token could not be checked")

    def check_client_authorization(self, result_authentication):
        """
        if endpoint == "/iot-repo" and method == "POST":
            if scope != "write:process":
                return False
        elif endpoint == "/process-repo" and method == "POST":
            if scoe != "write:process":
                return False
        """

    def check_user_authorization(self, result_authentication, request):
        allowed_to_access = False
        action = request.get("headers").get("target_method")
        resource = request.get("headers").get("target_uri")

        for role in result_authentication.get("realm_access").get("roles"):            
            access_policy_request = {
                "Subject": role,
                "Action": action,
                "Resource": ("endpoints" + resource).replace("/", ":")
            }

            print("check authorization for: " + json.dumps(access_policy_request))

            try:
                ladon_url = "{url}/access".format(url=os.environ["ladon_url"])
                print("send authorization request to: " + ladon_url)
                response = requests.post(ladon_url, data=json.dumps(access_policy_request)).json()
                print("authorization response: " + json.dumps(response))
                if response:
                    if response.get("Result"):
                        allowed_to_access = True
                        break
            except Exception:
                allowed_to_access = False 
                break
            

        return allowed_to_access
    

class Server():
    def __init__(self):
        # listen on all addresses (127.0.0.1, external)
        self.server_address = ('0.0.0.0', 8080)

    def start(self):
        httpd = BaseHTTPServer.HTTPServer(self.server_address, RequestHandler)
        httpd.serve_forever()



if __name__ == "__main__":
    print("Starting server")
    server = Server()
    server.start()

    