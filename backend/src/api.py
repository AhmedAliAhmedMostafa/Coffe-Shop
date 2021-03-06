import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

def check_request_body(request_body):
    if request_body is None:
        abort(400)
        print("request_body is None")
    if "title" not in request_body or "recipe" not in request_body:
        abort(400)
        print("title not in request_body or recipe not in request_body")
    # if not(type(request_body["recipe"]) is list):
    #     abort(400)
    
    # if "name" not in request_body['recipe'] or "color" not in request_body['recipe'] or "parts" not in request_body['recipe']:
    #     abort(400)
'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
db_drop_and_create_all()

## ROUTES
'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''

@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = Drink.query.all()
    print("drinks is",drinks)
    drinks_short_representation = [drink.short() for drink in drinks]
    return jsonify({
        "success":True,
        "drinks":drinks_short_representation
    })

'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    drinks = Drink.query.all()
    drinks_long_representation = [drink.long() for drink in drinks]
    return jsonify({
        "success":True,
        "drinks":drinks_long_representation
    })

'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def post_drink(payload):
    request_body = request.get_json()
    check_request_body(request_body)
    if not(type(request_body['recipe'])  is list):
        request_body['recipe'] = [request_body['recipe']]
    recipe_data = json.dumps(request_body['recipe'])
    print(recipe_data)
    new_drink = Drink(title=request_body['title'], recipe=recipe_data)
    new_drink.insert()
    print(new_drink.long())
    return jsonify({
        "success":True,
        "drinks":[new_drink.long()]
    })
    

'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def patch_drink(payload,id):
    target_tuple = Drink.query.get(id)
    if target_tuple is None:
        abort(404)
    request_body = request.get_json()
    if request_body is None:
        abort(400)
    if "title" not in request_body and "recipe" not in request_body:
        abort(400)
    if "title" in request_body:
        target_tuple.title = request_body['title']
    if "recipe" in request_body:
        for object in request_body["recipe"]:
            if "name" not in object or "color" not in object or "parts" not in object:
                abort(400)
        target_tuple.recipe = json.dumps(request_body['recipe'])
    
    target_tuple.update()
    return jsonify({
        "success":True,
        "drinks":[target_tuple.long()]
    })



'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload,id):
    target_tuple = Drink.query.get(id)
    if target_tuple is None:
        abort(404)
    target_tuple.delete()
    return jsonify({
        "success":True,
        "delete":id
    })

## Error Handling
'''
Example error handling for unprocessable entity
'''
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
                    "success": False, 
                    "error": 422,
                    "message": "unprocessable"
                    }), 422

'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False, 
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''
@app.errorhandler(400)
def not_found(error):
    return jsonify({
        "success":False,
        "error":400,
        "message":"Malformed Request."
    }),400
'''
@TODO implement error handler for 404
    error handler should conform to general task above 
'''
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success":False,
        "error":404,
        "message":"requested resource not found."
    })

'''
@TODO implement error handler for AuthError
    error handler should conform to general task above 
'''
@app.errorhandler(AuthError)
def authentication_error(error):
        return jsonify({
        "success":False,
        "error":error.status_code,
        "message":error.error
    }),error.status_code