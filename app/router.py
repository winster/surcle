from flask import render_template, request, flash, redirect, url_for, jsonify, abort, make_response, Blueprint
from flask_httpauth import HTTPBasicAuth
import json
import psycopg2
import sqlalchemy
import pyotp
import logging
from utils import email_otp, email_invite
from model import Account, Product, AccountProduct, AccountProductContact, AccountProductCalendar, session_commit, add_row, delete_row
from time import ctime
from datetime import datetime

FORMAT = '%(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

router = Blueprint('router', __name__)

auth = HTTPBasicAuth()


@auth.get_password
def get_password(username):
    try:
        act_rec = Account.query.filter_by(user_id=username).first()
        return act_rec.access_token
    except:
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
                map_products(user_id, request.json.get('products'))
                act_product_details = get_account_product_all(user_id)
                res= {'products' : act_product_details, 'access_token': access_token}
                return make_response(jsonify(res), 200)
            else:
                return make_response(jsonify({'result': 'invalid otp'}), 501)
        except Exception, e:
            logging.error(str(e))
            abort(404)


# deprecated as it is merged with auth api
@router.route('/v1.0/account_product', methods=['POST'])
def map_account_product():
    if request.json.get('access_token') is None or request.json.get('user_id') is None \
                or request.json.get('products') is None:
        abort(400)
    else:
        user_id = request.json.get('user_id')
        access_token = request.json.get('access_token')
        try:
            act_cur = Account.query.filter_by(user_id=user_id).first()
            if act_cur and act_cur.access_token == access_token:
                map_products(user_id, request.json.get('products'))
                res = make_response(jsonify({'result': 'success'}), 200)
                return res
            else:
                abort(400) #problem here, this will raise exception and get caught below
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/token', methods=['POST'])
@auth.login_required
def device_token():
    user_id = request.authorization.get('username')
    act_rec = Account.query.filter_by(user_id=user_id).first()
    if act_rec and request.json.get('token'):
        act_rec.device_token = request.json.get('token')
        act_rec.last_updated_on = ctime()
        session_commit()
        return make_response(jsonify({'result':'success'}), 200)
    else:
        abort(400)


@router.route('/v1.0/account_products', methods=['GET'])
@auth.login_required
def get_account_products():
    user_id = request.authorization.get('username')
    act_product_details = get_account_product_all(user_id)
    return make_response(jsonify(act_product_details), 200)


@router.route('/v1.0/account_product_contact', methods=['POST'])
@auth.login_required
def map_account_product_contact():
    if request.json.get('product_id') is None or request.json.get('contact_id') is None:
        abort(400)
    else:
        user_id = request.authorization.get('username')
        product_id = request.json.get('product_id')
        contact_id = request.json.get('contact_id')
        contact_name = request.json.get('name')
        thumbnail_url = request.json.get('thumbnail_url')
        contact_type = request.json.get('contact_type')
        try:
            act_cur = Account.query.filter_by(user_id=user_id).first()
            if act_cur and not user_id == contact_id:
                act_prod_cur = AccountProduct.query.filter_by(user_id=user_id, product_id=product_id).first()
                if act_prod_cur.role == contact_type:
                    return make_response(jsonify({'result': 'role and contact type cannot be the same'}), 501)
                else:
                    account_product_contact = AccountProductContact(user_id, product_id, contact_id,
                                                                    contact_name, thumbnail_url, contact_type)
                    add_contact = add_row(account_product_contact)
                    if not add_contact:
                        return make_response(jsonify({'result': 'contact already added'}), 501)
                    contact_cur = Account.query.filter_by(user_id=contact_id).first()
                    if contact_cur and contact_cur.access_token:
                        return make_response(jsonify({'result': 'success'}), 200)
                    else:
                        return make_response(jsonify({'result': 'contact does not exist in system'}), 200)
            else:
                abort(400)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/account_product_contact', methods=['DELETE'])
@auth.login_required
def delete_account_product_contact():
    if request.json.get('product_id') is None or request.json.get('contact_id') is None:
        abort(400)
    else:
        user_id = request.authorization.get('username')
        product_id = request.json.get('product_id')
        contact_id = request.json.get('contact_id')

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


@router.route('/v1.0/message', methods=['POST'])
@auth.login_required
def message():
    try:
        data = request.json
        from_act_rec = Account.query.filter_by(user_id=data.get('from')).first()
        if from_act_rec:
            to_act_rec = Account.query.filter_by(user_id=data.get('to')).first()
            if to_act_rec:
                #handleMessageTypes(data) TODO such as calendar update
                data['token'] = to_act_rec.device_token
                return make_response(jsonify(data), 200)
            else:
                return make_response(jsonify({'result': 'user to not present'}), 501)
        else:
            return make_response(jsonify({'result': 'user from not present'}), 501)
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
                    result[prod.product_id]['contacts'].append(con.as_dict_min())
            calendar_rec = AccountProductCalendar.query.filter_by(user_id=user_id, product_id=prod.product_id).first()
            if calendar_rec:
                result[prod.product_id]['calendar']= calendar_rec.calendar
    return result


# just for reference
@router.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
@auth.login_required
def update_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks) # tasks is a list
    if len(task) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    if 'description' in request.json and type(request.json['description']) is not unicode:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)

