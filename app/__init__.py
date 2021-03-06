from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
import gevent
from flask_sockets import Sockets

#app = Flask(__name__, static_url_path="/static")
app = Flask(__name__)

#office
#app.config['SQLALCHEMY_DATABASE_URI']= 'postgresql://postgres:postgres@localhost:5432/loopme'
#home
#app.config['SQLALCHEMY_DATABASE_URI']= 'postgresql://postgres:postgres@localhost:5432/postgres'
#production
app.config['SQLALCHEMY_DATABASE_URI']= 'postgresql://dtauvzjgkrbxun:8wDfm8Eb1T84_LZgh0qayGyQsg@ec2-174-129-29-118.compute-1.amazonaws.com:5432/dfini92nqen64n'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'some_secret'
db = SQLAlchemy(app)

print "db created"

"""Create Database migrations"""
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

print "db migrated"


from router import router, ws
app.register_blueprint(router)

sockets = Sockets(app)
sockets.register_blueprint(ws)

#@app.route('/')
#def root():
#    return app.send_static_file('index.html')
