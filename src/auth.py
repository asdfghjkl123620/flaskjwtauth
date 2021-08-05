from flask import Blueprint,request,jsonify
from werkzeug.security import check_password_hash,generate_password_hash
from src.constants.http_status_code import HTTP_400_BAD_REQUEST,HTTP_409_CONFLICT
import validators
from src.database import User,db

auth = Blueprint("auth",__name__,url_prefix="/api/v1/auth")

@auth.post('/register')
def register(request):
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    if len(password) < 6:
        return jsonify({'error':"Password is too short"}),HTTP_400_BAD_REQUEST
    if len(username) < 3:
        return jsonify({'error':"username is too short"}),HTTP_400_BAD_REQUEST
    if not username.isalnum() or " " in username:
        return jsonify({'error':"username 必須是一個 alphanumberic also not space"}),HTTP_400_BAD_REQUEST

    if not validators.email(email):
        return jsonify({'error':"email沒有經過驗證"}),HTTP_400_BAD_REQUEST

    if User.objects.filter_by(email=email).first is not None:
        return jsonify({'error':"email被使用了"}),HTTP_409_CONFLICT
    if User.objects.filter_by(username=username).first is not None:
        return jsonify({'error':"username被使用了"}),HTTP_409_CONFLICT


    pwd_hash=generate_password_hash(password) 
    user=User(username=username, password=pwd_hash, email=email)

    return "User Created"


@auth.get("/me")
def me():
    return {"User":"me"}