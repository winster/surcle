from flask import render_template, request, flash, redirect, url_for, jsonify, abort, make_response, Blueprint
from flask_httpauth import HTTPBasicAuth
from functools import wraps
import psycopg2
import sqlalchemy
from sqlalchemy import text
from app import db
import pyotp
import logging
from utils import email_otp, email_invite
from model import Account, Product, AccountProduct, AccountProductContact, AccountProductCalendar, session_commit, add_row, delete_row
from time import ctime
from datetime import datetime
import base64
import os
from gcloud import storage
import gevent
from flask_sockets import Sockets
import uuid,json,random,string
from xmppgcm import GCM, XMPPEvent
import ast

FORMAT = '%(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

router = Blueprint('router', __name__)
ws = Blueprint('ws', __name__)

auth = HTTPBasicAuth()
CLOUD_STORAGE_BUCKET = 'chirpy-images-bucket'

@auth.get_password
def get_password(username):
    try:
        act_rec = Account.query.filter_by(user_id=username).first()
        return act_rec.access_token
    except ValueError as error:
        print error.message
        return make_response(jsonify({'error': 'Unauthorized access'}), 403)


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 403)
    # return 403 instead of 401 to prevent browsers from displaying the default auth dialog


@router.errorhandler(400)
def not_found(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)


@router.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@router.errorhandler(401)
def not_found(error):
    return make_response(jsonify({'error': 'Auth failed'}), 401)


# READ
@router.route('/accounts')
def account_all():
    accounts = Account.query.all()
    return jsonify([account.as_dict() for account in accounts])


# Generate OTP, Create Account; Update OTP in Account
@router.route('/v1.0/otp', methods=['POST'])
def otp_send():
    print "inside sendotp"
    if not request.json.get('mobile'):
        abort(400)
    else:
        user_id = request.json.get('mobile')
        otp = pyotp.TOTP('base32secret3232').now()
        try:
            act_rec = Account.query.filter_by(user_id=user_id).first()
            if act_rec:
                act_rec.otp = otp
                act_rec.last_updated_on = ctime()
                session_commit()
                res = jsonify({'result': 'modified'})
            else:
                act = Account(user_id, otp)
                account_added = add_row(act)
                if account_added:
                    res = jsonify({'result': 'created'})
                else:
                    return make_response(jsonify({'result': 'failed'}), 501)
            email_otp(user_id, otp)
            return make_response(res, 200)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/products', methods=['GET'])
@auth.login_required
def get_products():
    """return jsonify({'products': map(make_public_task, tasks)})"""
    products = Product.query.all()
    return make_response(jsonify([product.as_dict() for product in products]))


# Validate OTP and Create Access Token
@router.route('/v1.0/auth', methods=['POST'])
def otp_validate():
    print request.json
    if request.json.get('mobile') is None or request.json.get('otp') is None :
        abort(400)
    else:
        user_id = request.json.get('mobile')
        otp = request.json.get('otp')
        try:
            act_rec = Account.query.filter_by(user_id=user_id).first()
            if act_rec and act_rec.otp == otp:
                time_difference = datetime.strptime(ctime(), "%a %b %d %H:%M:%S %Y") - act_rec.last_updated_on
                if time_difference.seconds > 600:
                    return make_response(jsonify({'result': 'otp expired'}), 502)
                access_token = pyotp.random_base32()
                act_rec.access_token = access_token
                act_rec.last_updated_on = ctime()
                session_commit()
                #map_products(user_id, request.json.get('products'))
                products = Product.query.all()
                res= {'products' : [product.as_dict() for product in products], 'access_token': access_token}
                return make_response(jsonify(res), 200)
            else:
                return make_response(jsonify({'result': 'invalid otp'}), 501)
        except Exception, e:
            logging.error(str(e))
            abort(404)


@router.route('/v1.0/account_products', methods=['POST'])
@auth.login_required
def map_account_product():
    if request.json.get('products') is None:
        abort(400)
    else:
        user_id = request.authorization.get('username')
        try:
            map_products(user_id, request.json.get('products'))
            act_product_details = get_account_product_all(user_id)
            res= {'products' : act_product_details}
            return make_response(jsonify(res), 200)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/token', methods=['POST'])
@auth.login_required
def device_token():
    print "inside device_token"
    user_id = request.authorization.get('username')
    act_rec = Account.query.filter_by(user_id=user_id).first()
    if act_rec and request.json.get('token'):
        act_rec.device_token = request.json.get('token')
        act_rec.online = True
        act_rec.last_updated_on = ctime()
        session_commit()
        return make_response(jsonify({'result':'success'}), 200)
    else:
        abort(400)


@router.route('/v1.0/socket', methods=['POST'])
@auth.login_required
def socket_connection():
    print "inside socket"
    user_id = request.authorization.get('username')
    act_rec = Account.query.filter_by(user_id=user_id).first()
    if act_rec and request.json.get('connection_id'):
        act_rec.connection_id = request.json.get('connection_id')
        act_rec.online = True
        act_rec.last_updated_on = ctime()
        session_commit()
        return make_response(jsonify({'result': 'success'}), 200)
    else:
        abort(400)


@router.route('/v1.0/offline', methods=['POST'])
@auth.login_required
def offline():
    print "inside offline"
    user_id = request.authorization.get('username')
    act_rec = Account.query.filter_by(user_id=user_id).first()
    if act_rec:
        act_rec.online = False
        act_rec.last_updated_on = ctime()
        session_commit()
        return make_response(jsonify({'result':'success'}), 200)
    else:
        abort(400)


# deprecated. All data has to be cached on server
@router.route('/v1.0/account_products', methods=['GET'])
@auth.login_required
def get_account_products():
    user_id = request.authorization.get('username')
    act_product_details = get_account_product_all(user_id)
    return make_response(jsonify(act_product_details), 200)


@router.route('/v1.0/account_product_contact', methods=['POST'])
@auth.login_required
def add_account_product_contact():
    if request.json.get('product_id') is None or request.json.get('contact_id') is None:
        abort(400)
    else:
        user_id = request.authorization.get('username')
        product_id = request.json.get('product_id')
        contact_id = request.json.get('contact_id')
        contact_name = request.json.get('name')
        #thumbnail_url = request.json.get('thumbnail_url')
        contact_type = request.json.get('contact_type')
        try:
            act_cur = Account.query.filter_by(user_id=user_id).first()
            if act_cur and not user_id == contact_id:
                act_prod_cur = AccountProduct.query.filter_by(user_id=user_id, product_id=product_id).first()
                if act_prod_cur.role == contact_type:
                    return make_response(jsonify({'result': 'role and contact type cannot be the same'}), 501)
                else:
                    account_product_contact = AccountProductContact(user_id, product_id, contact_id,
                                                                    contact_name, contact_type)
                    add_contact = add_row(account_product_contact)
                    if not add_contact:
                        return make_response(jsonify({'result': 'contact already added'}), 501)
                    contact_cur = Account.query.filter_by(user_id=contact_id).first()
                    if contact_cur and contact_cur.access_token:
                        return make_response(jsonify({'result':contact_cur.as_dict()}), 200)
                    else:
                        return make_response(jsonify({'result': 'contact does not exist in system'}), 200)
            else:
                abort(400)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/product/<int:product_id>/contact/<string:contact_id>', methods=['DELETE'])
@auth.login_required
def delete_account_product_contact(product_id, contact_id):
    if product_id is None or contact_id is None:
        abort(400)
    else:
        user_id = request.authorization.get('username')
        #product_id = request.json.get('product_id')
        #contact_id = request.json.get('contact_id')

        try:
            act_cur = Account.query.filter_by(user_id=user_id).first()
            if act_cur and not user_id == contact_id:
                act_prod_cont = AccountProductContact.query.filter_by(user_id=user_id, product_id=product_id, contact_id=contact_id).first()
                delete_rec = delete_row(act_prod_cont)
                if not delete_rec:
                    return make_response(jsonify({'result': 'failed'}), 501)
                else:
                    return make_response(jsonify({'result': 'success'}), 200)
            else:
                abort(400)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/product/<int:product_id>/contact/<string:contact_id>', methods=['GET'])
@auth.login_required
def get_account_product_contact(product_id, contact_id):
    try:
        cal_rec = AccountProductCalendar.query.filter_by(user_id=contact_id, product_id=product_id).first()
        if cal_rec:
            return make_response(jsonify(cal_rec.calendar), 200)
        else:
            return make_response(jsonify({'result': 'user calendar not present'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)


@router.route('/v1.0/invite/<string:contact_id>', methods=['GET'])
@auth.login_required
def invite_contact(contact_id):
    try:
        act_rec = Account.query.filter_by(user_id=contact_id).first()
        if act_rec:
            email_invite(request.authorization.get('username'), contact_id)
            return make_response(jsonify({'result' : 'success. invite sent'}), 200)
        else:
            return make_response(jsonify({'result': 'user not present'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)


@router.route('/v1.0/product/<int:product_id>/calendar', methods=['POST'])
@auth.login_required
def set_calendar(product_id):
    try:
        user_id = request.authorization.get('username')
        calendar_json = request.json.get('calendar')
        act_rec = AccountProduct.query.filter_by(user_id=user_id, product_id=product_id).first()
        if act_rec and act_rec.role == 'PROVIDER':
            cal_rec = AccountProductCalendar.query.filter_by(user_id=user_id, product_id=product_id).first()
            if not cal_rec:
                calendar = AccountProductCalendar(user_id, product_id, calendar_json, None)
                add_row(calendar)
                return make_response(jsonify({'result': 'success. Calendar added'}), 200)
            else:
                cal_rec.calendar = calendar_json
                session_commit()
                return make_response(jsonify({'result': 'success. Calendar modified'}), 200)
        else:
            return make_response(jsonify({'result': 'failed. User is not a PROVIDER'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)


#
#def check_token(username, token):
#    try:
#        act_rec = Account.query.filter_by(user_id=username).first()
#        if act_rec and act_rec.access_token == token:
#            return True
#        else:
#            return False
#    except:
#        return False
#
#def requires_auth(f):
#    @wraps(f)
#    def decorated(*args, **kwargs):
#        auth = request.authorization
#        if not auth or not check_token(auth.username, auth.password):
#            return make_response(jsonify({'error': 'Unauthorized access'}), 403)
#        return f(*args, **kwargs)
#    return decorated
#
@router.route('/v1.0/message', methods=['POST'])
@auth.login_required
def message():
    try:
        input = request.json
        to_act_rec = Account.query.filter_by(user_id=input.get('to')).first()
        if to_act_rec:
            #handleMessageTypes(input.data) TODO such as calendar update
            result = {'online': to_act_rec.online, 'token': to_act_rec.device_token}
            if to_act_rec.online is True:
                result['connection_id'] = to_act_rec.connection_id
            return make_response(jsonify(result), 200)
        else:
            return make_response(jsonify({'result': 'user to not present'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)
       

#
#  image upload
#
@router.route('/v1.0/image',methods=['POST'])
@auth.login_required
def upload_images():
    try:
        user_id = request.authorization.get('username')
        file = request.files['uploaded_file']
        filename = file.filename
        #folder = 'app/static/images/{0}/'.format(user_id)
        #completeName = folder+filename
        #dir = os.path.dirname(completeName)
        #if not os.path.exists(dir):
        #    os.makedirs(dir)
        #file.save(completeName)
        #file.close()
        completeName = "{0}-{1}".format(user_id,filename)
        # Create a Cloud Storage client.
        gcs = storage.Client()
        # Get the bucket that the file will be uploaded to.
        bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)
        # Create a new blob and upload the file's content.
        blob = bucket.blob(completeName)
        blob.upload_from_string(
            file.read(),
            content_type=file.content_type
        )
        print "after file is uploaded::{0}".format(blob.public_url)
        # The public URL can be used to directly access the uploaded file via HTTP.        
        return make_response(jsonify({'url': blob.public_url}), 200)
    except Exception, e:
        logging.error(str(e))
        abort(400)


# Update image url to Account
@router.route('/v1.0/image_url', methods=['POST'])
@auth.login_required
def update_image_url():
    print request.json
    if request.json.get('url') is None or request.json.get('type') is None :
        abort(400)
    else:
        user_id = request.authorization.get('username')
        img_type = request.json.get('type')
        url = request.json.get('url')
        try:
            act_rec = Account.query.filter_by(user_id=user_id).first()
            if act_rec:
                if img_type == 'logo':
                    act_rec.logo_url = url
                elif img_type == 'profilepic':
                    act_rec.profilepic_url = url
                act_rec.last_updated_on = ctime()
                session_commit()
                return make_response(jsonify({'result': 'success'}), 200)
            else:
                return make_response(jsonify({'result': 'Account does not exist'}), 501)
        except Exception, e:
            logging.error(str(e))
            abort(404)
    

@router.route('/v1.0/account/<string:user_id>', methods=['GET'])
@auth.login_required
def get_account(user_id):
    try:
        act_rec = Account.query.filter_by(user_id=user_id).first()
        if act_rec:
            act_res = {'profilepic_url' : act_rec.profilepic_url, 'logo_url' : act_rec.logo_url}
            return make_response(jsonify(act_res), 200)
        else:
            return make_response(jsonify({'result': 'user not present'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)


@router.route('/v1.0/invite_status', methods=['POST'])
@auth.login_required
def invite_status():
    print "inside invite_status"
    if request.json is None:
        abort(400)
    else:
        users = "','".join(request.json)
        users = "'{0}'".format(users)
        try:        
            sql = text('select user_id from account where user_id in ({0})'.format(users))
            result = db.engine.execute(sql)
            user_list = []
            for row in result:
                user_list.append(row[0])
            print "before sending response"
            return make_response(jsonify(user_list), 200)
        except Exception, e:
            logging.error(str(e))
            abort(400)


def map_products(user_id, products):
    if products:
        for product_id, prod in request.json.get('products').iteritems():
            role = prod.get("role")
            act_prod_rec = AccountProduct.query.filter_by(user_id=user_id, product_id=product_id).first()
            if not act_prod_rec:
                account_product = AccountProduct(user_id, product_id, role)
                add_row(account_product)
            else:
                act_prod_rec.role = role
                session_commit()


def get_account_product_all(user_id):
    result = {}
    products = AccountProduct.query.filter_by(user_id=user_id).all()
    if products:
        for prod in products:
            result[prod.product_id] = {'contacts': [], 'calendar': {}, 'role': prod.role}
            contacts_list = AccountProductContact.query.\
                filter_by(user_id=user_id, product_id=prod.product_id).all()
            if contacts_list:
                for con in contacts_list:
                    con_dict = con.as_dict_min()
                    contact_cur = Account.query.filter_by(user_id=con.contact_id).first()
                    if contact_cur and contact_cur.access_token:
                        con_dict['profilepic_url'] = contact_cur.profilepic_url
                        con_dict['logo_url'] = contact_cur.logo_url                        
                        con_dict['status'] = 0
                    else:
                        con_dict['status'] = 1                   
                    result[prod.product_id]['contacts'].append(con_dict)
            calendar_rec = AccountProductCalendar.query.filter_by(user_id=user_id, product_id=prod.product_id).first()
            if calendar_rec:
                result[prod.product_id]['calendar']= calendar_rec.calendar
    return result

socket_clients = {}

@ws.route('/wssocket')
#@auth.login_required
def web_socket(socket):
    logging.debug('inside web_socket')
    connection_id = random_id()
    socket_clients[connection_id] = socket
    socket.send(json.dumps({'connection_id':connection_id}))
    while not socket.closed:
        message = socket.receive()
        if message != 'ping':
            logging.debug('message received : {0}'.format(message))
            payload = json.loads(message)
            to_act_rec = Account.query.filter_by(user_id=payload['to']).first()
            if to_act_rec:
                #handleMessageTypes(input.data) TODO such as calendar update
                if to_act_rec.online is True and to_act_rec.connection_id and to_act_rec.connection_id in socket_clients:
                    logging.debug("sending via websocket")
                    socket_clients[to_act_rec.connection_id].send(message)
                else:
                    logging.debug("sending via gcm")
                    options = { 'delivery_receipt_requested': True }
                    xmpp.send_gcm(to_act_rec.device_token, payload, options, onAcknowledge)
                        

@router.route('/v1.0/delete_socket', methods=['DELETE'])
@auth.login_required
def delete_socket():
    if not request.json.get('connection_id'):
        abort(400)
    else:
        connection_id = request.json.get('connection_id')
        del socket_clients[connection_id]
        return make_response(jsonify({'result': 'success'}), 200)   


# Message delivery receipt as well as payment card acknowledgement are handled here. 
#Could not find a proper name, hence given receipt
@router.route('/v1.0/receipt', methods=['POST'])
@auth.login_required
def receipt():
    input = request.json
    logging.debug('receipt: {0}', json.dumps(input))
    if not input['user'] or not input['token'] or not input['to'] or not input['product_id'] or not input['message_id'] or not input['message_type']:
        msg = {error:"Input missing",errorCode:"101"}
        return make_response(jsonify(msg))
    
    payload =   {
                    'product_id':input['product_id'], 
                    'user':input['user'], 
                    'type':input['message_type'], 
                    'id':input['message_id']
                }
    to_act_rec = Account.query.filter_by(user_id=input['to']).first()
    if to_act_rec:
        if to_act_rec.online is True and to_act_rec.connection_id and to_act_rec.connection_id in socket_clients:
            socket_clients[to_act_rec.connection_id].send(payload)
        else:
            options = { 'delivery_receipt_requested': True }
            xmpp.send_gcm(to_act_rec.device_token, payload, options, onAcknowledge)
    return make_response(jsonify({'result':'success'}))
            

def random_id():
    rid = ''
    for x in range(8): rid += random.choice(string.ascii_letters + string.digits)
    return rid

def onDisconnect(draining):
    print 'inside onDisconnect'
    xmpp.connect(('gcm-preprod.googleapis.com', 5236), use_ssl=True)

def onSessionStart(queue_length):
    logging.debug('inside onSessionStart {0}'.format(queue_length))

def onReceipt(data):
    logging.debug('inside onReceipt {0}'.format(data))

def onMessage(data):
    logging.debug('inside onSessionStart {0}'.format(data))

def onAcknowledge(error, message_id, _from):
    if error != None:
        logging.debug('not acknowledged by GCM')
    logging.debug('id - {0} : from - {1}'.format(message_id, _from))


logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(message)s')
logging.debug("Starting up")

xmpp = GCM('640723155266@gcm.googleapis.com', 'AIzaSyC6jFXGk50i1dEfP0GJn5exE29j6z8O4h0')
xmpp.add_event_handler(XMPPEvent.CONNECTED, onSessionStart)
xmpp.add_event_handler(XMPPEvent.DISCONNECTED, onDisconnect)
xmpp.add_event_handler(XMPPEvent.RECEIPT, onReceipt)
xmpp.add_event_handler(XMPPEvent.MESSAGE, onMessage)

xmpp.connect(('gcm-preprod.googleapis.com', 5236), use_ssl=True)
# xmpp.connect(('gcm-xmpp.googleapis.com', 5235), use_ssl=True)

#while True:
#    xmpp.process(block=True)
