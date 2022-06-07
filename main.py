from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth


import constants
from datetime import datetime

app = Flask(__name__)

app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# Oauth2 Credentials
CLIENT_ID = constants.client_id
CLIENT_SECRET = constants.client_secret

# auth0 redirect
DOMAIN = '493-spring2022-hongbri.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

USERS = constants.users
BOOKS = constants.books
LIBRARY = constants.library

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=('https://{}/.well-known/openid-configuration').format(DOMAIN)
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)

# to verify JWT but does not raise error
def verify_jwt_pass(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False

        return payload
    else:
        return False

#  welcome screen to redirect to Auth0 login
# if user is logged in the user profile with JWT is shown
@app.route('/')
def index():
    if session:
        user = session.get("user")
        if not user:
            session.clear()
            return 'error logging in please refresh and try again'
        userprofile = user["userinfo"]
    else:
        userprofile = ''
    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=json.dumps(userprofile, indent=4),
    )


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt(code):
    payload = verify_jwt(request)
    return payload

# check function to see if user is in datastore entity
def check_user(username, unique_id):

    # a query is made using the user id token as a unique id
    query = client.query(kind=USERS)
    query.add_filter("unique_id", "=", unique_id)
    user_list = list(query.fetch())

    # if nothing is returned then user is not in datastore
    # a new entry is made
    if not user_list:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({'username': username,
                         'unique_id': unique_id,
                         'library': []})
        client.put(new_user)


# The following were referenced from https://auth0.com/docs/quickstart/webapp/python
# this login is mainly for POSTMAN to make requests
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        content = request.get_json()
        username = content["username"]
        password = content["password"]

        body = {'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET
                }
        headers = {'content-type': 'application/json'}
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        response = json.loads(r.text)
        token = response['id_token']
        claims = jwt.get_unverified_claims(token)
        h = jwt.get_unverified_header(token)
        check_user(claims['name'], claims['sub'])
        return r.text, 200, {'Content-Type': 'application/json'}

    # users using web page will be redirected to a callback
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

# returns all users in entity
@app.route("/users", methods=["GET"])
def users():
    if request.method == "GET":
        accept(request)
        query = client.query(kind=USERS)
        user = list(query.fetch())
        user_list = {}
        for i in user:
            for j in i:
                if j == 'unique_id' and i[j] not in user_list:
                    user_list[i[j]] = i
        return jsonify(user_list), 200
    return {'Error': 'Method not allowed'}, 405


# callback to login page for auth0
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    check_user(token['userinfo']['name'], token['userinfo']['sub'])
    session["user"] = token
    return redirect("/")


# clears session to logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# Error class to raise error if the request was made without accepting application/json
class AcceptError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AcceptError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# error method to raise error
def accept(request):
    if not request.accept_mimetypes['application/json']:
        raise AcceptError({"code": "no_json", 'description': 'application/json not found in Accept header'}, 406)


# post new books
# get existing books
# this is not related to user
@app.route('/books', methods=['POST', 'GET'])
def book_get_post():
    accept(request)
    if request.method == 'POST':
        content = request.get_json()

        # these fields must be included in new entry
        if ("title" and "genre" and "published_year" and "author") not in content:
            return {'Error': 'The request object is missing at least one of the required attributes'}, 400

        # a book with the same title cannot be entered
        book_title = client.query(kind=BOOKS)
        book_title.add_filter("title", "=", content["title"])
        book_check = list(book_title.fetch())
        if book_check:
            return {'Error': 'The book already exists in the database'}, 400

        new_book = datastore.entity.Entity(key=client.key(BOOKS))
        new_book.update({"title": content["title"],
                         "genre": content["genre"],
                         "published_year": content["published_year"],
                         "author": content["author"],
                         "library_id": [],
                         "libraries": {}})
        client.put(new_book)

        # a url is created for the new book
        url_self = request.base_url + '/' + str(new_book.key.id)
        new_book.update({"id": new_book.key.id,
                         "self": url_self})
        client.put(new_book)
        return jsonify(new_book), 201
    elif request.method == 'GET':
        # pagination of all books in datastore
        query = client.query(kind=BOOKS)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"books": results}
        if next_url:
            output["next"] = next_url
        return jsonify(output)


# when book gets updated the library info corresponding to it updates
def update_book_in_lib(lid, bid, title):
    lib_key = client.key(LIBRARY, lid)
    library = client.get(key=lib_key)
    library['books'][bid]['title'] = title
    client.put(library)


# Put or PATCH book with new information
# Deletes book
# book is not a protected entity but users must logged into edit
@app.route('/books/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def book_put_delete(id):
    verify_jwt(request)
    book_key = client.key(BOOKS, int(id))
    book = client.get(key=book_key)

    # check if book is in datastore
    if not book:
        return {'Error': 'No books with this book id exists'}, 404
    if request.method == 'GET':
        accept(request)
        return jsonify(book)
    elif request.method == 'PUT':
        content = request.get_json()

        # check all required fields are entered
        # library_id and libraries field is not altered by user
        if "title" not in content or "genre" not in content or "published_year" not in content or "author" not in content:
            return {'Error': 'The request object is missing at least one of the required attributes'}, 400
        book.update({"title": content["title"],
                     "genre": content["genre"],
                     "published_year": content["published_year"],
                     "author": content["author"],
                     "library_id": book['library_id'],
                     "libraries": book['libraries']})
        client.put(book)

        # if a book is linked with any libraries the library is updated
        if book['library_id']:
            for i in book['library_id']:
                update_book_in_lib(i, id, book['title'])
        return ('', 200)
    if request.method == 'PATCH':
        content = request.get_json()

        # for every field that is in the request
        for i in content:

            # library_id and libraries is not altered
            if i == 'library_id' or i == 'libraries':
                continue
            book.update({i: content[i]})
        client.put(book)

        # any libraries associated with this book is updated
        if book['library_id']:
            for i in book['library_id']:
                update_book_in_lib(i, id, book['title'])
        return ('', 200)
    elif request.method == 'DELETE':
        verify_jwt(request)
        query = client.query(kind=LIBRARY)
        query.add_filter("book_id", "=", book.id)
        lib_list = list(query.fetch())
        print(lib_list)
        for i in lib_list:
            library = client.get(key=i.key)
            del library["books"][id]
            library['book_id'].remove(book.id)
            client.put(library)
        client.delete(book_key)
        return ('', 204)


'''
POST: Adds new library
GET: Returns all existing library
'''


# Create a library if the Authorization header contains a valid JWT
# Get all library own by user
# if no user is specified returns all public library

@app.route('/library', methods=['POST', 'GET'])
def library_get_post():
    accept(request)
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        if ("name" and "description" and "public") not in content:
            return {'Error': 'The request object is missing at least one of the required attributes'}, 400
        date = datetime.now().strftime("%x")
        day = datetime.now().strftime("%a")
        time = datetime.now().strftime("%X")
        creation = day + " " + date + " " + time
        url_self = request.base_url + '/'
        new_library = datastore.entity.Entity(key=client.key(LIBRARY))
        new_library.update({'name': content['name'],
                            'description': content['description'],
                            'public': content['public'],
                            'date': creation,
                            "owner": payload["sub"],
                            "book_id": [],
                            "books": {}})
        client.put(new_library)
        url_self += str(new_library.key.id)
        new_library.update({'id': new_library.key.id,
                            'self': url_self})
        client.put(new_library)

        query = client.query(kind=USERS)
        query.add_filter("unique_id", "=", payload["sub"])
        user_key = list(query.fetch())
        user = client.get(key=user_key[0].key)
        user["library"].append(new_library.id)
        client.put(user)
        return jsonify(new_library), 201
    elif request.method == 'GET':
        query = client.query(kind=LIBRARY)
        if not verify_jwt_pass(request):
            query.add_filter("public", "=", True)
        else:
            payload = verify_jwt(request)
            query.add_filter("owner", "=", payload["sub"])
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"library": results}
        if next_url:
            output["next"] = next_url
        return jsonify(output)
    else:
        return 'Method not recognized'

'''
GET: Returns a specific library
'''
@app.route('/library/<lid>', methods=['GET'])
def lib_get(lid):
    lib_key = client.key(LIBRARY, int(lid))
    library = client.get(key=lib_key)
    if not library:
        return {'Error': 'No library with this library id exists'}, 404

    # private libraries not owned by user will return an error
    if not library['public']:
        payload = verify_jwt_pass(request)
        if payload['sub'] != library['owner']:
            return {'Error': 'This library is private'}, 403
    if request.method == 'GET':
        accept(request)
        return jsonify(library), 200
    else:
        return 'Method not recognized'


# when library gets updated the book info corresponding to it updates
def update_lib_in_book(lid, bid, name):
    book_key = client.key(BOOKS, bid)
    book = client.get(key=book_key)
    book['libraries'][lid]['name'] = name
    client.put(book)
'''
PUT: Edits a library
PATCH: Edits one or more attribute of the library
DELETE: Deletes the library
'''
@app.route('/library/<id>', methods=['PUT', 'PATCH', 'DELETE'])
def lib_put_del(id):
    payload = verify_jwt(request)
    lib_key = client.key(LIBRARY, int(id))
    library = client.get(key=lib_key)
    if not library:
        return {'Error': 'No library with this library id exists'}, 404
    if payload["sub"] != library["owner"]:
        return {'Error': 'This library is owned by someone else'}, 403
    user_query = client.query(kind=USERS)
    user_query.add_filter("unique_id", "=", payload["sub"])
    user_key = list(user_query.fetch())
    user = client.get(key=user_key[0].key)
    print(user)
    if request.method == 'PUT':
        date = datetime.now().strftime("%x")
        day = datetime.now().strftime("%a")
        time = datetime.now().strftime("%X")
        creation = day + " " + date + " " + time + "(edited)"
        content = request.get_json()

        # book_id and books cannot be changed by PUT or PATCH
        book_id = library['book_id']
        books = library['books']

        library.update({'name': content['name'],
                        'description': content['description'],
                        'public': content['public'],
                        'date': creation,
                        "owner": payload["sub"],
                        "book_id": book_id,
                        "books": books})
        client.put(library)
        if library['book_id']:
            for i in library['book_id']:
                update_lib_in_book(str(library.id), i, library['name'])
        return '', 200
    if request.method == 'PATCH':
        content = request.get_json()
        for i in content:
            # book_id and books cannot be changed by PUT or PATCH
            if i == 'book_id' or i == 'books':
                continue
            library.update({i: content[i]})
        client.put(library)
        if library['book_id']:
            for i in library['book_id']:
                update_lib_in_book(str(library.id), i, library['name'])
        return '', 200
    elif request.method == 'DELETE':
        # delete library from books
        query = client.query(kind=BOOKS)
        query.add_filter("library_id", "=", library.id)
        b = list(query.fetch())
        for i in b:
            book = client.get(key=i.key)
            del book['libraries'][id]
            book['library_id'].remove(library.id)
            client.put(book)
        # delete library from users
        if lib_key in user["library"]:
            user["library"].remove(lib_key)
            client.put(user)
        client.delete(lib_key)
        return '', 204
    else:
        return 'Method not recognized'


'''
PUT: Assigns a book to a library
DELETE: Removes the book from the user library
        does not delete book
'''


@app.route('/library/<lid>/books/<bid>', methods=['PUT', 'DELETE'])
def add_delete_book(bid, lid):
    payload = verify_jwt(request)
    book_key = client.key(BOOKS, int(bid))
    book = client.get(key=book_key)
    lib_key = client.key(LIBRARY, int(lid))
    library = client.get(key=lib_key)
    if not book or not library:
        return {"Error": "The specified book and/or library does not exist"}, 404
    if payload['sub'] != library["owner"]:
        return {"Error": "This library belongs to another user"}, 403
    if request.method == 'PUT':
        if book.id in library["book_id"] or library.id in book["library_id"]:
            return {"Error": "The book is already in this list"}, 403
        library["book_id"].append(book.id)
        library["books"][bid] = {'id': book.id, 'title': book['title'], 'url': book['self']}
        book['library_id'].append(library.id)
        book['libraries'][lid] = {'id': library.id, 'name': library['name'], 'url': library['self']}
        client.put(library)
        client.put(book)
        return '', 204
    if request.method == 'DELETE':
        if book.id not in library['book_id'] or library.id not in book['library_id']:
            return {"Error": "No books with this book id is in this library with this library id"}, 404
        else:
            del library['books'][bid]
            del book['libraries'][lid]
            library['book_id'].remove(book.id)
            book['library_id'].remove(library.id)
            client.put(library)
            client.put(book)
            return '', 204

# this method is to clean everything up after testing
@app.route('/delete_everything', methods=['DELETE'])
def delete_everything():
    l = client.query(kind=LIBRARY)
    q = list(l.fetch())
    for i in q:
        client.delete(i)
    l = client.query(kind=USERS)
    q = list(l.fetch())
    for i in q:
        client.delete(i)
    l = client.query(kind=BOOKS)
    q = list(l.fetch())
    for i in q:
        client.delete(i)
    return '', 204
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
