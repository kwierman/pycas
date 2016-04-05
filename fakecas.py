#!/usr/bin/env python
from optparse import OptionParser
from pymongo import MongoClient
import logging
import urllib
import flask
import json

logger=logging.getLogger(__name__)

app = flask.Flask(__name__)

client = MongoClient("127.0.01.1", 27017)
osf_db = client['osf20130903']
user_collection = osf_db['user']

def set_normal_headers(resp):
    resp.headers['Content-type'] = 'text/html'
    resp.headers["Access-Control-Allow-Origin"] =  "*"
    resp.headers["Access-Control-Allow-Headers"] =  "Range, Content-Type, Authorization, Cache-Control, X-Requested-With"
    resp.headers["Access-Control-Expose-Headers"] =  "Range, Content-Type, Authorization, Cache-Control, X-Requested-With"
    resp.headers["Cache-control"] =  "no-store, no-cache, must-revalidate, max-age=0"

def set_xml_headers(resp):
    set_normal_headers(resp)
    resp.headers['Content-type'] = 'text/xml'

def set_json_headers(resp):
    set_normal_headers(resp)
    resp.headers['Content-type'] = 'text/json'

@app.route('/', methods=['POST','GET'])
def prototype():
    logger.info("Prototype")
    resp = resp = flask.Response("")
    set_normal_headers(resp)
    return resp, 200

@app.route('/', methods=['OPTIONS'])
def options():
    logger.info("OPTIONS: {}".format("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE"))
    resp = flask.Response("", 204)
    resp.headers["Access-Control-Allow-Methods"]="GET, PUT, POST, DELETE"
    return resp

@app.route('/login', methods=['POST','GET'])
def login():
    redirect_url = flask.request.args['service']
    username=None
    try:
        if bool(flask.request.args['auto']):
            username = str(flask.request.form['username'])
        else:
            username = str(flask.request.args['username'])
        redirect_url =  flask.request.args["service"]
    except KeyError:
        return flask.Response("Improperly formatted response"), 503
    if '?' in redirect_url:
        redirect_url+='&ticket={}'.format(username)
    else:
        redirect_url+='?ticket={}'.format(username)
    logger.info(redirect_url)
    return flask.redirect(redirect_url)

@app.route('/logout', methods=['POST'])
def logout():
    logger.info(flask.request.form('service'))
    return flask.redirect(flask.request.form('service'))


@app.route('/oauth2/profile', methods=['GET'])
def oauth2_profile():
    auth = flask.request.headers.get('Authorization').replace("Bearer ","")
    user = user_collection.find_one({"_id":auth})
    js ={'id': user["_id"],
            'attributes':{
                'lastName': user["family_name"],
                'firstName': user['given_name']
            }
        }
    logger.info(str(js))
    resp = flask.Response(json.dumps(js))
    set_json_headers(resp)
    return resp

@app.route('/p3/serviceValidate', methods=['GET'])
def validate_service():
    logger.info("In prototype action")
    username = flask.request.args['ticket']
    user = user_collection.find_one({'emails': username})

    ret='<?xml version="1.0" encoding="UTF-8"?><cas:serviceResponse xmlns:cas="{}"><cas:authenticationSuccess><cas:user>{}</cas:user><cas:attributes><cas:isFromNewLogin>{}</cas:isFromNewLogin><cas:authenticationDate>{}</cas:authenticationDate><cas:givenName>{}</cas:givenName><cas:familyName>{}</cas:familyName><cas:longTermAuthenticationRequestTokenUsed>false</cas:longTermAuthenticationRequestTokenUsed><accessToken>{}</accessToken><username>{}</username></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>'.format( "http://www.yale.edu/tp/cas",
                 user["_id"],
                 "true",
                 "Eh",
                 user["given_name"],
                 user["family_name"],
                 user["_id"],
                 user["username"] )
    resp = flask.Response(ret)
    set_xml_headers(resp)
    return resp


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-a", "--addr", dest="addr",
                      help="Address to run server on", metavar="ADDR", default='127.0.0.1')
    parser.add_option("-p", "--port", dest="port",
                      help="Port to run server on", metavar="PORT", default=8080)
    parser.add_option("-f", "--file", dest="file",
                      help="Logging File Name", metavar="FILE", default="fakecas.log")
    (options, args) = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)#filename=options.file,

    logger.info("Starting FakeCAS server...")
    app.run(host=options.addr, port = int(options.port))
