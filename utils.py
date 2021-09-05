from models import Users,Usersauth,Eglesson_attendance
import os
from hashlib import pbkdf2_hmac
import datetime
import jwt
from flask_mysqldb import MySQLdb
from flask import Blueprint, json, request, Response, jsonify
from flask.helpers import make_response

from app import db
from settings import JWT_SECRET_KEY

import logging
import traceback
import logging.config

logging.config.fileConfig('logging.cfg', disable_existing_loggers=False)
logger = logging.getLogger(__name__)


def generate_salt():
    salt = os.urandom(16)
    return salt.hex()


def generate_hash(plain_password, password_salt):
    password_hash = pbkdf2_hmac(
        "sha256",
        b"%b" % bytes(plain_password, "utf-8"),
        b"%b" % bytes(password_salt, "utf-8"),
        10000,
    )
    return password_hash.hex()


def generate_jwt_token(content):
    print(content)
    print(JWT_SECRET_KEY)
    encoded_content = jwt.encode(content, JWT_SECRET_KEY, algorithm="HS256")
    token = str(encoded_content).split("'")[1]
    return token


def validate_user_input(input_type, **kwargs):
    if input_type == "authentication":
        if len(kwargs["email"]) <= 255 and len(kwargs["password"]) <= 255:
            return True
        else:
            return False


def validate_user(email, password):
    current_user = Usersauth.query.filter_by(email=email).all()
    print(current_user)
    if len(current_user) == 1:
        saved_password_hash = current_user[0].password_hash
        saved_password_salt = current_user[0].password_salt
        password_hash = generate_hash(password, saved_password_salt)

        if password_hash == saved_password_hash:
            user_id = current_user[0].id
            jwt_token = generate_jwt_token({"id": user_id})
            return jwt_token
        else:
            return False

    else:
        return False

def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=15),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                JWT_SECRET_KEY,
                algorithm='HS256'
            )
        except Exception as e:
            return e


def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            pyload= jwt.decode(auth_token, JWT_SECRET_KEY)
            return pyload['id']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


def fetch_attendance(regstriationnumber):
    try:
        user = Users.query.filter_by(registration=regstriationnumber).first()
        return user
    except Exception as e:
        logger.error(e)
        logger.error(e, exc_info=True)
        return False
    except:
        logger.error("uncaught exception: %s", traceback.format_exc())
        return False


def fetch_campus_attendance(regstriationnumber):
    learner = Eglesson_attendance.query.filter_by(registration_number=regstriationnumber).first()
    return learner

def db_read(query, params=None):
    cursor = db.connection.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)

    entries = cursor.fetchall()
    cursor.close()

    content = []

    for entry in entries:
        content.append(entry)

    return content


def db_write(query, params):
    cursor = db.connection.cursor()
    try:
        cursor.execute(query, params)
        db.connection.commit()
        cursor.close()

        return True

    except MySQLdb._exceptions.IntegrityError:
        cursor.close()
        return False

