#!/usr/bin/env python
import xml.etree.cElementTree as ET
from optparse import OptionParser
from pymongo import MongoClient
import logging
import urllib
import flask
import json

logger=logging.getLogger("fakecas")

app = flask.Flask("fakecas")

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
    root = ET.Element('cas:serviceResponse')
    root.attrib['xmlns:cas'] = "http://www.yale.edu/tp/cas"
    auth = ET.SubElement(root, 'cas:authenticationSuccess')
    ET.SubElement(auth, 'cas:user').text = user['_id']
    attr = ET.SubElement(auth, 'cas:attributes')
    ET.SubElement(attr, 'cas:isFromNewLogin').text='true'
    ET.SubElement(attr, 'cas:authenticationDate').text='eh'
    ET.SubElement(attr, 'cas:givenName').text=user['given_name']
    ET.SubElement(attr, 'cas:familyName').text=user['family_name']

    ET.SubElement(attr, 'cas:longTermAuthenticationRequestTokenUsed').text = 'true'
    ET.SubElement(attr, 'accessToken').text=user['_id']
    ET.SubElement(attr, 'username').text=user['username']

    resp = flask.Response(ET.tostring(root))
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
