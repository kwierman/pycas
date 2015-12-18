#!/usr/bin/env python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from pymongo import MongoClient
import logging
from optparse import OptionParser

from sys import version as python_version
from cgi import parse_header, parse_multipart
import cgi

logger=logging.getLogger(__name__)



class PrototypeAction:
    """
        Override this to create new actions for the server to take
    """
    def __init__(self, handler):
        self.handler=handler
    def action(self):
        """
            Called when
        """
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

        self.redirect_url =  self.handler.params["service"]

        try:
            
            if bool(self.handler.params['auto']):
                self.username = str(self.handler.postvars["username"][0])
            else:
                self.username     =  self.handler.params["username"]
            self.redirect_url =  self.handler.params["service"]
        except KeyError:
            print "Improperly Formatted Request: "
            print self.handler.params
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
        logger.info("In prototype action")
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



POST_ROUTES= {'/': PrototypeAction,
"/login":LoginAction}

GET_ROUTES= {
    '/' : PrototypeAction,
    "/favicon.ico" : PrototypeAction,
    "/logout":LogoutAction,
    "/oauth2/profile":OAuthAction,
    "/p3/serviceValidate":ServiceValidateAction
    }


class CASHandler(BaseHTTPRequestHandler):

    client = MongoClient("127.0.01.1", 27017)
    osf_db = client['osf20130903']
    user_collection = osf_db['user']
    logger=logging.getLogger("CASHandler")  

    def _set_normal_header(self):
        self.logger.info("Setting Normal Header")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
    def _set_xml_header(self):
        self.send_response(200)
        self.logger.info("Setting XML Header")
        self.send_header('Content-type', 'text/xml')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Access-Control-Expose-Headers", "Range, Content-Type, Authorization, Cache-Control, X-Requested-With")
        self.send_header("Cache-control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
    def _set_json_header(self):
        self.logger.info("Setting JSON Header")
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

        self.logger.info("GET: {}".format( self.parsed_path) )
        action = GET_ROUTES[self.parsed_path ](self)
        action.action()

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        self._set_params()

        self.logger.info("POST: {}".format( self.parsed_path) )

        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        if ctype == 'multipart/form-data':
            self.postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.getheader('content-length'))
            self.postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            self.postvars = {}

        action = POST_ROUTES[self.parsed_path ](self)
        action.action()


    def do_OPTIONS(self):
        self.logger.info("OPTIONS: {}".format("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE") )
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE")
        self.end_headers()

def run(server_class=HTTPServer, handler_class=CASHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logger.info("Starting FakeCAS server...")
    httpd.serve_forever()
    client.disconnect()

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-p", "--port", dest="port",
                      help="Port to run server on", metavar="PORT", default=8080)
    parser.add_option("-f", "--file", dest="file",
                      help="Logging File Name", metavar="FILE", default="fakecas.log")
    (options, args) = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)#filename=options.file,
    run(port=options.port)
