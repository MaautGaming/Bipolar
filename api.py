from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = '/home/sipher/Work/Bipolar/book.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    amazon_url = db.Column(db.String(80))
    author = db.Column(db.String(50))
    genre = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
   

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/book', methods=['GET'])
@token_required
def get_all_books(current_user):
    books = Book.query.filter_by(user_id=current_user.id).all()

    output = []

    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['title'] = book.title
        book_data['amazon_url'] = book.amazon_url
        book_data['author'] = book.author
        book_data['genre'] = book.genre
        output.append(book_data)

    return jsonify({'books' : output})

@app.route('/book/<book_id>', methods=['GET'])
@token_required
def get_one_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if not book:
        return jsonify({'message' : 'No book found!'})

    book_data = {}
    book_data['id'] = book.id
    book_data['title'] = book.title
    book_data['amazon_url'] = book.amazon_url
    book_data['author'] = book.author
    book_data['genre'] = book.genre
        
    return jsonify(book_data)

@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):
    
    data = request.get_json()

    new_book = Book(title=data['title'], amazon_url=data['amazon_url'], author=data['author'], genre=data['genre'],  user_id=current_user.id)
    db.session.add(new_book)
    db.session.commit()

    return jsonify({'message' : "book added!"})

@app.route('/book/<book_id>', methods=['PUT'])
@token_required
def complete_book(current_user, book_id):
    
    update_book = data.get_json()

    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if not book:
        return jsonify({'message' : 'No book found!'})

    
    update_book.title = book.title
    update_book.amazon_url = book.amazon_url
    update_book.author = book.author
    update_book.genre = book.genre
    db.session.commit()

    return jsonify({'message' : 'book item has been updated!'})

@app.route('/book/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):
    book = Book.query.filter_by(id=book_id, user_id=current_user.id).first()

    if not book:
        return jsonify({'message' : 'No book found!'})

    db.session.delete(book)
    db.session.commit()

    return jsonify({'message' : 'book item deleted!'})

if __name__ == '__main__':
    app.run(debug=True)