from flask import Blueprint, json, request, Response, jsonify
from flask.helpers import make_response
from utils import (
    fetch_attendance,
    fetch_campus_attendance,
    validate_user_input,
    generate_salt,
    generate_hash,
    # db_write,
    validate_user,
    decode_auth_token,

)
from models import Usersauth
from app import db
import logging
import traceback
import logging.config

authentication = Blueprint("authentication", __name__)

logging.config.fileConfig('logging.cfg', disable_existing_loggers=False)
logger = logging.getLogger(__name__)

#Default Path
@authentication.route("/",methods=["GET"])
def helloWorld():
    try:
        return "<h1>Welcome to the API Portal</h1>"
    except OSError as e:
        logger.error(e)
        logger.error(e, exc_info=True)

# REGISTER A USER AS AN API USER
@authentication.route("/register", methods=["POST"])
def register_user():
    user_email = request.json["email"]
    user_password = request.json["password"]
    user_confirm_password = request.json["confirm_password"]

    if user_password == user_confirm_password and validate_user_input(
        "authentication", email=user_email, password=user_password
    ):
        password_salt = generate_salt()
        password_hash = generate_hash(user_password, password_salt)
        user = Usersauth.query.filter_by(email=user_email).first()
        if not user:
            try:
                user = Usersauth(
                    id = len(Usersauth.query.all())+1,
                    email=user_email,
                    password_salt=password_salt,
                    password_hash=password_hash
                )

                db.session.add(user)
                db.session.commit()

                responseObject = {
                    'status': 'success',
                    'message': 'Successfully saved User',
                    'user': {
                        'userid': user.id,
                        'email': user.email
                    }
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'Failure',
                    'message': 'Operation failed'
                }
                logger.error('Error: '+ e)
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                    'status': 'Failure',
                    'message': 'User Already Exist'
                }
            return make_response(jsonify(responseObject)), 400
    else:
        responseObject = {
                    'status': 'Failure',
                    'message': 'User Already Exists'
                }
        return make_response(jsonify(responseObject)), 400

   
# LOGGING IN TO GET ACCESS TOKEN
@authentication.route("/login", methods=["POST"])
def login_user():
    try:
        user_email = request.json["email"]
        user_password = request.json["password"]

        user_token = validate_user(user_email, user_password)

        if user_token:
            return jsonify({"jwt_token": user_token})
        else:
            Response(status=401)
    except Exception as e:
        logger.error(e)
        logger.error(e, exc_info=True)

# FETCHING ATTENDANCE
@authentication.route("/attendance", methods=["GET"])
def get_attendance():
    # get the auth token
    auth_header = request.json['token']
    if auth_header !='':
        auth_token=auth_header
        resp = decode_auth_token(auth_token)
        
        if not isinstance(resp, str):
            data = fetch_attendance(request.json['registrationnumber'])

            responseObject = {
                'status': 'success',
                'data': {
                    'user_id': data.id,
                    'email': data.email,
                    'nationality':data.nationality
                }
            }
            return make_response(jsonify(responseObject)), 200
        else:
            print(resp)
            responseObject = {
            'status': 'fail',
            'message': resp
        }
        return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'fail',
            'message': 'No token Provided!'
        }
    return make_response(jsonify(responseObject)), 402

#FETCH Attendance without Authentication
@authentication.route("/freeAttendance", methods=["GET"])
def freeAttendance():
    try:
        data = fetch_attendance(request.json['registrationnumber'])

        responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': data.id,
                        'email': data.email,
                        'nationality':data.nationality
                    }
                }
        return make_response(jsonify(responseObject)), 200 
    except Exception as e:
        logger.error(e)
        logger.error(e, exc_info=True)
        return e
    except:
        logger.error("uncaught exception: %s", traceback.format_exc())
        return False
        

@authentication.route("/campusAttendance", methods=["POST"])
def freeCampusAttendance():
    data = fetch_campus_attendance(request.json['registrationnumber'])

    responseObject = {
                'status': 'success',
                'data': {
                    'learnerid': data.learner_id,
                    'attendance_code': data.attendance_code,
                    'registration_number':data.registration_number
                }
            }
    return make_response(jsonify(responseObject)), 200 
