#!/usr/bin/env python


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from pymongo import MongoClient

class PrototypeAction:
    def __init__(self, handler):
        self.handler=handler
    def action(self):
        print "In Prototype Action. Path Not Recognized."
        self.handler._set_headers()
        self.handler.wfile.write("<html><body><h1>Reached Prototype. Improperly Formatted</h1></body></html>")

    def normal_response(self):
        self.handler.send_response(200)
        self.handler.send_header('Content-type', 'text/html')
        self.handler.send_header("Access-Control-Allow-Origin", "*")
        self.handler.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.handler.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.handler.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.handler.end_headers()
    def redirect_to(self, redirect):
        print "Redirecting to: ", redirect
        self.handler.send_response(301)
        self.handler.send_header("Location", redirect)
        self.handler.end_headers()

class LoginAction(PrototypeAction):
    def action(self):
        """
            At login, the fakecas server pulls out the redirect URL with the ticket at the end 
            ticket=<username>
        """
        try:

            self.username     =  self.handler.params["username"]
            self.redirect_url =  self.handler.params["service"]
        except KeyError:
            print "Improperly Formatted Request: "
            self.handler._set_headers()
            self.handler.wfile.write("<html><body><h1>Improperly Formatted Request</h1></body></html>")
            return

        print "In Login Action: ", self.username

        if "?" in self.redirect_url:
            self.redirect_url += "&ticket="+self.username
        else:
            self.redirect_url+="?ticket="+self.username
        self.redirect_to(self.redirect_url)

class LogoutAction(PrototypeAction):
    def action(self):
        try:

            self.username     =  self.handler.params["username"]
            self.redirect_url =  self.handler.params["service"]
        except KeyError:
            print "Improperly Formatted Request: "
            self.handler._set_headers()
            self.handler.wfile.write("<html><body><h1>Improperly Formatted Request</h1></body></html>")
            return
        self.redirect_to(self.redirect_url)


class OAuthAction(PrototypeAction):
    def action(self):
        auth = self.handler.headers.getheader('Authorization').replace("Bearer ","")
        user = self.handler.user_collection.find_one({"_id": auth})
        self.handler._set_json_header()
        ret="""
        {"id":, {}
        "attributes":{
            "lastName" : {},
            "firstName" : {}
            }
        }
        """.format(user["_id"],user["family_name"],user["family_name"] )
        self.handler.wfile.write(ret)       


class ServiceValidateAction(PrototypeAction):
    def action(self):
        self.username     =  self.handler.params["ticket"]
        user = self.handler.user_collection.find_one({"emails": self.username})
        self.handler._set_xml_header()
        ret='<?xml version="1.0" encoding="UTF-8"?><cas:serviceResponse xmlns:cas="{}"><cas:authenticationSuccess><cas:user>{}</cas:user><cas:attributes><cas:isFromNewLogin>{}</cas:isFromNewLogin><cas:authenticationDate>{}</cas:authenticationDate><cas:givenName>{}</cas:givenName><cas:familyName>{}</cas:familyName><cas:longTermAuthenticationRequestTokenUsed>false</cas:longTermAuthenticationRequestTokenUsed><accessToken>{}</accessToken><username>{}</username></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>'.format( "http://www.yale.edu/tp/cas",
                     user["_id"],
                     "true",
                     "Eh",
                     user["given_name"],
                     user["family_name"],
                     user["_id"],
                     user["username"] )
        self.handler.wfile.write(ret)



POST_ROUTES= {"/login":LoginAction}

GET_ROUTES= {
    "/login":LoginAction,
    '/' : PrototypeAction,
    "/favicon.ico" : PrototypeAction,
    "/logout":LogoutAction,
    "/oauth2/profile":OAuthAction,
    "/p3/serviceValidate":ServiceValidateAction
    }


class CASHandler(BaseHTTPRequestHandler):
    client = MongoClient('localhost', 27017)
    osf_db = client['osf20130903']
    user_collection = osf_db['user']

    def _set_normal_header(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
    def _set_xml_header(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/xml')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
    def _set_json_header(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()       
    def _set_headers(self):
        self._set_normal_header()

    def _set_params(self):
        path_parts = self.path.split("?")
        self.parsed_path = path_parts[0]
        self.params={}
        if len(path_parts)>1:
            param_path = path_parts[1]
            for p in param_path.split("&"):
                if p.split('=')>1:
                    self.params[p.split('=')[0]]=p.split('=')[1]
                else:
                    self.params[p.split('=')[0]]=''

    def do_GET(self):
        self._set_params()

        print "Getting: ", self.parsed_path
        action = GET_ROUTES[self.parsed_path ](self)
        #self.wfile.write("<html><body><h1>hi!</h1></body></html>")
        action.action()

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        # Doesn't do anything with posted data
        self._set_headers()
        self.wfile.write("<html><body><h1>POST!</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
        self.end_headers()

def run(server_class=HTTPServer, handler_class=CASHandler, port=8080):



    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting FakecasServer...'
    httpd.serve_forever()
    client.disconnect()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()