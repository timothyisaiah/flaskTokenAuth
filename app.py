import os
import sys

from flask import Flask,Blueprint
from flask_cors import CORS
from flask_mysqldb import MySQL
from settings import MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB,MYSQL_USER1, MYSQL_PASSWORD1, MYSQL_DB1
from flask_sqlalchemy import SQLAlchemy


sys.path.insert(0, os.path.dirname(__file__))


app = Flask(__name__)


app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
app.config['SQLALCHEMY_DATABASE_URI']='mysql://everestg_auth_user:eg123auth.org@127.0.0.1/everestg_user_authentication'
app.config['SQLALCHEMY_BINDS']={
    'grader': "mysql://everestg_grader_user:eg123.org@127.0.0.1/everestg_grader_2",
    'campus': "mysql://root:@127.0.0.1/everestg_campus_kayiwa"
}
app.debug =0

db = SQLAlchemy(app)

from blueprint_auth import authentication

app.register_blueprint(authentication, url_prefix="/api/auth")

application = app
