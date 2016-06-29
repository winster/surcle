from flask import render_template, request, flash, redirect, url_for, jsonify, abort, make_response, Blueprint
from flask_httpauth import HTTPBasicAuth
import json
import psycopg2
import sqlalchemy
import pyotp
import logging
from utils import email_otp, email_invite
from model import Account, Product, AccountProduct, AccountProductContact, session_commit, add_row, delete_row
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


tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol',
        'done': False
    },
    {
        'id': 3,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web',
        'done': False
    }
]


def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task


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
            act = Account(user_id, otp)
            account_added = add_row(act)
            if account_added:
                res = jsonify({'result': 'created'})
            else:
                act_cur = Account.query.filter_by(user_id=user_id).first()
                logging.info(act_cur.as_dict())
                act_cur.otp = otp
                act_cur.last_updated_on = ctime()
                session_commit()
                res = jsonify({'result': 'modified'})
            email_otp(user_id, otp)
            return make_response(res, 200)
        except Exception, e:
            logging.error(str(e))
            abort(400)


# Validate OTP and Create Access Token
@router.route('/v1.0/auth', methods=['POST'])
def otp_validate():
    if request.json.get('mobile') is None or request.json.get('otp') is None :
        abort(400)
    else:
        user_id = request.json.get('mobile')
        otp = request.json.get('otp')
        try:
            act_cur = Account.query.filter_by(user_id=user_id).first()
            if act_cur and act_cur.otp == otp:
                time_difference = datetime.strptime(ctime(), "%a %b %d %H:%M:%S %Y") - act_cur.last_updated_on
                if time_difference.seconds > 600:
                    res = make_response(jsonify({'result': 'otp expired'}), 400)
                    return res
                access_token = pyotp.random_base32()
                act_cur.access_token = access_token
                act_cur.last_updated_on = ctime()
                session_commit()
                res = make_response(jsonify({'access_token': access_token}), 200)
                return res
            else:
                abort(400)
        except Exception, e:
            logging.error(str(e))
            abort(400)


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
                for prod in request.json.get('products'):
                    product_id = prod.get("product_id")
                    role = prod.get("role")
                    act_prod_cur = AccountProduct.query.filter_by(user_id=user_id, product_id=product_id).first()
                    if not act_prod_cur:
                        account_product = AccountProduct(user_id, product_id, role)
                        add_row(account_product)
                    else:
                        act_prod_cur.role = role
                        session_commit()

                res = make_response(jsonify({'result': 'success'}), 200)
                return res
            else:
                abort(400)
        except Exception, e:
            logging.error(str(e))
            abort(400)


@router.route('/v1.0/products', methods=['GET'])
def get_products():
    """return jsonify({'products': map(make_public_task, tasks)})"""
    products = Product.query.all()
    return make_response(jsonify([product.as_dict() for product in products]))


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


@router.route('/v1.0/account_product_contact/<string:contact_id>', methods=['GET'])
@auth.login_required
def get_account_product_contact(contact_id):
    try:
        act_cur = Account.query.filter_by(user_id=contact_id).first()
        if act_cur:
            return make_response(jsonify(act_cur.as_dict), 200)
        else:
            return make_response(jsonify({'result': 'user not present'}), 501)
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
            return make_response(jsonify({'result':'success. invite sent'}), 200)
        else:
            return make_response(jsonify({'result': 'user not present'}), 501)
    except Exception, e:
        logging.error(str(e))
        abort(400)


@router.route('/todo/api/v1.0/tasks', methods=['POST'])
@auth.login_required
def create_task():
    if not request.json or not 'title' in request.json:
        abort(400)
    task = {
        'id': tasks[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    tasks.append(task)
    return jsonify({'task': make_public_task(task)}), 201


@router.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
@auth.login_required
def update_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
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

    task[0]['title'] = request.json.get('title', task[0]['title'])
    task[0]['description'] = request.json.get('description', task[0]['description'])
    task[0]['done'] = request.json.get('done', task[0]['done'])
    return jsonify({'task': make_public_task(task[0])})


@router.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
@auth.login_required
def delete_task(task_id):
    task = filter(lambda t: t['id'] == task_id, tasks)
    if len(task) == 0:
        abort(404)
    tasks.remove(task[0])
    return jsonify({'result': True})
