from sqlalchemy.exc import SQLAlchemyError
from time import ctime
from app import db
from stripped_string import StrippedString
import logging
FORMAT = '%(message)s'
logging.basicConfig(format=FORMAT,level=logging.DEBUG)


# Create the Account Class
class Account(db.Model):
    user_id = db.Column(StrippedString, primary_key=True)
    otp = db.Column(StrippedString, nullable=False)
    access_token = db.Column(StrippedString, nullable=True)
    created_on = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    last_updated_on = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def __init__(self, user_id, otp):
        self.user_id = user_id
        self.otp = otp
        self.created_on = ctime()
        self.last_updated_on = ctime()

    def __repr__(self):
        return '<Account %r>' % self.user_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# Create the Products Class
class Product(db.Model):
    product_id = db.Column(db.INTEGER, primary_key=True)
    name = db.Column(StrippedString, nullable=False)
    description = db.Column(StrippedString, nullable=False)
    created_on = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    last_updated_on = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.created_on = ctime()
        self.last_updated_on = ctime()

    def __repr__(self):
        return '<Product %r>' % self.product_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# Create the AccountProducts Class
class AccountProduct(db.Model):
    product_id = db.Column(db.INTEGER, primary_key=True)
    user_id = db.Column(StrippedString, primary_key=True)
    role = db.Column(StrippedString, nullable=False)

    def __init__(self, user_id, product_id, role):
        self.user_id = user_id
        self.product_id = product_id
        self.role = role

    def __repr__(self):
        return '<AccountProduct %r>' % self.product_id

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# Create the AccountProductContact Class
class AccountProductContact(db.Model):
    user_id = db.Column(StrippedString, primary_key=True)
    product_id = db.Column(db.INTEGER, primary_key=True)
    contact_id = db.Column(StrippedString, primary_key=True)
    name = db.Column(StrippedString, nullable=False)
    contact_type = db.Column(StrippedString, nullable=False)

    def __init__(self, user_id, product_id, contact_id, name, contact_type):
        self.user_id = user_id
        self.product_id = product_id
        self.contact_id = contact_id
        self.name = name
        self.contact_type = contact_type

    def __repr__(self):
        return '<AccountProductContact user_id=%s, product_id=%s, contact_id=%s, name=%s, contact_type=%s  >'\
               % (self.user_id, self.product_id, self.contact_id, self.name, self.contact_type)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def add_row(row):
    try:
        db.session.add(row)
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False


def delete_row(row):
    try:
        db.session.delete(row)
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False



def session_commit():
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        reason = str(e)
        logging.info(reason)
        raise e

db.create_all()

if len(Product.query.all()) == 0:
    db.session.add(Product('TAXI', 'Manage all taxi operations here'));
    db.session.add(Product('DOCTOR', 'Manage all doctor interations here'));
    db.session.commit()

#if __name__ == '__main__':
#    manager.run()