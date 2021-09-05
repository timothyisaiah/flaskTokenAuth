from app import db


class Usersauth(db.Model):
    __tablename__ = "usersauth"

    id = db.Column('id',db.Integer, primary_key=True,autoincrement=False)
    email = db.Column('email',db.String(255), nullable=False)
    password_salt = db.Column('password_salt',db.String(255), nullable=False)
    password_hash = db.Column('password_hash',db.String(255), nullable=False)

    def __init__(self,id, email, password_salt, password_hash):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.password_salt = password_salt



class Users(db.Model):
    __bind_key__ = 'grader'
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key=True)
    name= db.Column('name',db.String(255))
    nationality = db.Column('nationality',db.String(255))
    email = db.Column('email',db.String(255))
    registration = db.Column('registration',db.String(255))
    contact = db.Column('contact',db.String(255))
    role = db.Column('role',db.String(255))
    status = db.Column('status',db.Integer)
    school_id = db.Column('school_id',db.BigInteger)
    program = db.Column('program',db.String(255))
    dob = db.Column('dob',db.String(255))
    course = db.Column('course',db.Integer)
    year = db.Column('year',db.Integer)
    month = db.Column('month',db.String(255))
    email_verified_at = db.Column('email_verified_at',db.DateTime)
    password = db.Column('password',db.String(255))
    remember_token = db.Column('remember_token',db.String(100))
    flutter_api= db.Column('flutter_api',db.String(255)) 
    created_at= db.Column('created_at',db.DateTime) 
    updated_at = db.Column('updated_at',db.DateTime)

# class Classes(db.Model):

class Eglesson_attendance(db.Model):
    __bind_key__ = 'campus'
    __tablename__ = 'eglesson_attendance'
    attendance_id = db.Column('attendance_id',db.Integer, primary_key=True)
    learner_id = db.Column('learner_id',db.Integer)
    class_id = db.Column('class_id',db.Integer)
    exercise_score = db.Column('exercise_score',db.String(30))
    tutor_remark = db.Column('tutor_remark',db.String(1000))
    session_id = db.Column('session_id',db.Integer)
    attendance_code = db.Column('attendance_code',db.String(8))
    tutor_rating = db.Column('tutor_rating',db.Integer)
    registration_number = db.Column('registration_number',db.String(255))
    attendance_confirmed = db.Column('attendance_confirmed',db.String(4))