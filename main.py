from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = '9b7799e4e69e8419ea54596df9bd214948b3b0c5c1ebdf3510d6b67a4145f3cc'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/flaaskapp'  # Replace with your MongoDB URI

mongo = PyMongo(app)


class User:
    def __init__(self, public_id, name, email, password):
        self.public_id = public_id
        self.name = name
        self.email = email
        self.password = password

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
		return f(current_user, *args, **kwargs)

	return decorated

@app.route("/", methods=["GET"])
def index():
      return jsonify({"Message": "Welcome"})
      

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = mongo.db.users.find()
    output = []
    for user in users:
        output.append({
            'public_id': user['public_id'],
            'name': user['name'],
            'email': user['email']
        })

    return jsonify({'users': output})

# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = mongo.db.users.find_one({'email': auth.get('email')})

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user['password'], auth.get('password')):
        token = jwt.encode({
            'public_id': user['public_id'],
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
        return make_response(jsonify({'token': token.decode('UTF-8')}), 201)

    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )

# signup route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if not user:
        public_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            'public_id': public_id,
            'name': name,
            'email': email,
            'password': hashed_password
        })
        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please log in.', 202)

if __name__ == "__main__":

	app.run(debug = True, port=8000, host="0.0.0.0")
