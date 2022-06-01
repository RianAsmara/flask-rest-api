from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import sys
import jwt
from datetime import datetime, timedelta
from  werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_cors import CORS, cross_origin
from dotenv import load_dotenv
from functools import wraps
import cloudinary
import cloudinary.uploader
import cloudinary.api
from cloudinary.utils import cloudinary_url

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'secretbangetnih!'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
db = SQLAlchemy(app)

class Item(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(80), nullable=False)
  content = db.Column(db.String(), nullable=False)
  file_name = db.Column(db.Text, nullable=True)
  file_path = db.Column(db.Text, nullable=True)
  mime_type = db.Column(db.Text, nullable=True)
  size = db.Column(db.Text, nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String())

db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        return  f(current_user, *args, **kwargs)
  
    return decorated

@app.route('/users', methods=['GET'])
@token_required
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email
        })
    return jsonify({
      'success': True,
      'code': 200,
      'message': 'Successfully retrieved all users',
      'users': output
      })

@app.route('/login', methods=['POST'])
def login():
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({
          'success': False,
          'code': 400,
          'message': 'Please fill all the fields',
          })
  
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()
  
    if not user:
        return jsonify({
          'success': False,
          'code': 404,
          'message': 'User does not exist',
          })
  
    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({
            'success': True,
            'code': 200,
            'message': 'Successfully logged in',
            'token': token.decode('UTF-8')
        }), 200)

    return jsonify({
          'success': False,
          'code': 400,
          'message': 'Invalid credentials',
          })

@app.route('/register', methods=['POST'])
def signup():
    data = request.form
  
    name, email = data.get('name'), data.get('email')
    password = data.get('password')
  
    user = User.query\
        .filter_by(email = email)\
        .first()
    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
  
        return jsonify({
          'success': True,
          'code': 200,
          'message': 'Successfully registered',
          })
    else:
        return jsonify({
          'success': False,
          'code': 400,
          'message': 'User already exists',
          })

@app.route('/items', methods=['GET'])
@token_required
def get_items():
  items = []
  for item in db.session.query(Item).all():
    del item.__dict__['_sa_instance_state']
    items.append(item.__dict__)
  return jsonify({
    'success': True,
    'code': 200,
    'message': 'OK',
    'items': items
  })

@app.route('/item/create', methods=['POST'])
@cross_origin()
def create_item():
  app.logger.info('in upload route')

  cloudinary.config(cloud_name = os.getenv('CLOUD_NAME'), api_key=os.getenv('API_KEY'), 
    api_secret=os.getenv('API_SECRET'))
  upload_result = None
  if request.method == 'POST':
    title = request.form['title']
    content = request.form['content']
    file = request.files['file']
    app.logger.info('%s file', file)
    if file:
      upload_result = cloudinary.uploader.upload(file)
      app.logger.info(upload_result)
      
      db.session.add(Item(
        title=title,
        content=content,
        file_name=upload_result.get('asset_id'),
        file_path=upload_result.get('secure_url'),
        mime_type=upload_result.get('format'),
        size=upload_result.get('bytes')
        ))

    db.session.commit()
  return jsonify({
    'success': True,
    'code': 200,
    'message': 'OK'
  })

if __name__ == '__main__':
    app.run(debug=True)