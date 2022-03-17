import datetime
import jwt
import uuid

from flask import Flask, jsonify, request
from utility.DBConnectivity import create_mongo_connection
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "84b99a1fa5754f03ac75fff2f81b6079"

##############################################################
##############################################################
################## Item Kart #################################
##############################################################
##############################################################

# Create an application for Item Kart
# The application should have the following functionality:
# 1. User login (Authentication) DONE
# 2. List all the items available in the shop as per category (With limits and offsets)
# 3. Add the items to the cart (Authentication required) DONE
# 4. List the items present in the cart (Authentication required)
# 5. Remove and Edit items of the cart (Authentication required)
# You can start writing your code for the above mentioned functionalities from here

def authenticate(fun):
    @wraps(fun)
    def decorator(*args, **kwargs):
        try:
            token = request.headers.get('Authorization')
            if token:
                token = token.split(' ')[-1]
                token_body = jwt.decode(str(token), app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
                return fun(*args, **kwargs)
            return jsonify(message='Authentication credentials were not provided.')
        except Exception as e:
            return jsonify(message="Invalid token.")
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():
    try:
        request_data = request.json
        email = request_data.get("email_id")
        if create_mongo_connection().users.find_one({"email": email}):
            return jsonify(message="User Already Exist"), 409
        first_name = request_data.get("first_name")
        last_name = request_data.get("last_name")
        password = request_data.get("password")
        hashed_password = generate_password_hash(password, method='sha256')
        user_info = dict(_id=uuid.uuid4().hex, first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        create_mongo_connection().users.insert_one(user_info)
        return jsonify(message="User added sucessfully"), 201
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/login", methods=["POST"])
def login():
    try:
        request_data = request.json
        email = request_data.get("email_id")
        password = request_data.get("password")
        auth_user = create_mongo_connection().users.find_one({"email": email})
        if auth_user:
            if check_password_hash(auth_user.get('password'), password):
                token = jwt.encode(
                    {
                        'public_id' : auth_user.get('_id'),
                        'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)
                    },
                    app.config['JWT_SECRET_KEY'],
                    "HS256"
                )
                return jsonify(message="Login Succeeded!", access_token=token), 201
            return jsonify(message="Invalid Credentials."), 401
        return jsonify(message="User not found. Please register first."), 412
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/add_to_cart", methods=['POST'])
@authenticate
def add_to_cart():
    try:
        request_data = request.json
        items_to_be_saved = []
        items = request_data.get("items")
        if items:
            for item in items:
                items_to_be_saved.append({
                    "_id": uuid.uuid4().hex,
                    "price": item.get("price"),
                    "description": item.get("description"),
                    "tags": item.get("tags")
                })
            db = create_mongo_connection()
            db.carts.insert_many(items_to_be_saved)
            return jsonify(message="Item added successfully."), 201
        return jsonify(message="Empty items provided."), 412
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/update_cart", methods=['PUT'])
@authenticate
def update_cart():
    try:
        _id = request.args.get('_id')
        if _id:
            data_to_be_updated = {
                "description": request.args.get("description"),
                "name": request.args.get("name"),
                "tags": request.args.get("tags"),
                "price": request.args.get("price"),
            }
            db = create_mongo_connection()
            condition = {"_id": _id}
            query = {"$set": data_to_be_updated}
            updated = db.carts.find_one_and_update(condition, query)
            if updated:
                return jsonify(message="Item updated successfully."), 200
            return jsonify(message="Item not found."), 412
        return jsonify(message="Item id required."), 412
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/get_cart_item", methods=['GET'])
@authenticate
def get_cart_item():
    try:
        db = create_mongo_connection()
        documents = db.carts.find({})
        return jsonify(data=list(documents)), 200
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/delete_cart", methods=['DELETE'])
@authenticate
def delete_cart():
    try:
        _id = request.args.get('_id')
        if _id:
            db = create_mongo_connection()
            is_removed = db.carts.find_one_and_delete({"_id": _id})
            if is_removed:
                return jsonify(message="Item removed successfully."), 200
            return jsonify(message="Item not found."), 412
        return jsonify(message="Item id required."), 412
    except Exception as e:
        return jsonify(message=str(e)), 412


@app.route("/get_items_by_category", methods=['GET'])
def get_items_by_category():
    try:
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', 5))
        category = request.args.get('category')
        if category:
            db = create_mongo_connection()
            documents = db.items.find({"name": category}).limit(limit).skip(offset)
            count = db.items.count_documents({"name": category})
            response = {
                'data': list(documents),
                'next_offset': offset + limit,
                'limit': 5,
                'total_count': count
            }
            return jsonify(response), 200
        return jsonify(message="Category is empty."), 412
    except Exception as e:
        return jsonify(message=str(e)), 412


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
