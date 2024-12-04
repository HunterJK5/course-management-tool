from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage
import requests
import json
import io
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS = "users"
COURSES ="courses"

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

CLIENT_ID = 'ja3UFmiI5Uj6WvcUjtyCs5r3MGlpFZdT'
CLIENT_SECRET = 'b8EWnZStU4CX2ZARNY5BunlTR-R3DRFNGN3WMqmRtWHvduEVaRioEzhoosvK-JdQ'
DOMAIN = 'dev-nne7u8ez3m8dwwfr.us.auth0.com'

AVATAR_BUCKET = 'kottwith-assignment6'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)
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
)

# The Auth0 and JWT code section is adapted from https://auth0.com/docs/quickstart/backend/python/01-
#authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-
#jwt-validation-decorator

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
        
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
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
                issuer="https://"+ DOMAIN+"/"
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


@app.route('/')
def index():
    return "Please Navigate to /login in order to begin using the Course Manger."

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "username" not in content or "password" not in content:
        return (ERROR_400, 400)
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
            }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    response = json.loads(r.text)
    if "id_token" not in response:
        return(ERROR_401, 401)
    token = response["id_token"]
    login_response = {"token": token}
    return login_response, 200, {'Content-Type':'application/json'}


@app.route("/" + USERS, methods=["GET"])
def get_users():
    #check for valid JWT
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)
    
    user = get_access(payload)
    
    if not user or user["role"] != "admin":
        return (ERROR_403, 403)
    
    query = client.query(kind=USERS)
    results = list(query.fetch())
    return_obj = []

    for r in results:
        curr_r = {}
        curr_r["id"] = r.key.id
        curr_r["role"] = r["role"]
        curr_r["sub"] = r["sub"]
        return_obj.append(curr_r)

    return (return_obj, 200)


@app.route("/" + USERS + "/<int:id>", methods=["GET"])
def get_user(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)
    
    access = get_access(payload)

    if not access or access["role"] != "admin":
        if access["id"] != id:
            return (ERROR_403, 403)
        
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if not user:
        return (ERROR_403, 403)
    
    response = {
        "id": user.key.id,
        "role": user["role"],
        "sub": user["sub"]
    }

    if "avatar_url" in user:
        response["avatar_url"] = user["avatar_url"]

    if access["role"] == "student" or access["role"] == "instructor":
        response["courses"] = []

    return (response, 200)
    

@app.route("/" + USERS + "/<int:id>/avatar", methods=["POST"])
def post_avatar(id):
    if "file" not in request.files:
        return(ERROR_400, 400)
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)
    
    access = get_access(payload)

    if not access or access["id"] != id:
        return (ERROR_403, 403)
    
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if not user:
        return (ERROR_403, 403)
    
    file_obj = request.files["file"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    
    user.update({
        "avatar": file_obj.filename,
        "avatar_url": f"{request.host_url}users/{id}/avatar"
    })

    client.put(user)

    response = {
        "avatar_url": f"{request.host_url}users/{id}/avatar"
        }

    return(response, 200)


@app.route("/" + USERS + "/<int:id>/avatar", methods=["GET"])
def get_avatar(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)
    
    access = get_access(payload)

    if not access or access["id"] != id:
        return (ERROR_403, 403)
    
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if not user:
        return (ERROR_403, 403)

    if "avatar" not in user:
        return (ERROR_404, 404)
    
    file_name = user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)


@app.route("/" + USERS + "/<int:id>/avatar", methods=["DELETE"])
def delete_avatar(id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)

    access = get_access(payload)

    if not access or access["id"] != id:
        return (ERROR_403, 403)

    user_key = client.key(USERS, id)
    user = client.get(key=user_key)

    if not user:
        return (ERROR_403, 403)

    if "avatar" not in user:
        return (ERROR_404, 404)

    file_name = user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()

    del user["avatar"]
    del user["avatar_url"]
    client.put(user)

    return "", 204


@app.route("/" + COURSES, methods=["POST"])
def post_course():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return (ERROR_401, 401)

    access = get_access(payload)

    if not access or access["role"] != "admin":
        return (ERROR_403, 403)

    content = request.get_json()

    course = validate_course_body(content)

    if not course:
        return (ERROR_400, 400)

    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update({
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "term": course["term"],
        "instructor_id": course["instructor_id"]
    })
    client.put(new_course)

    new_course["id"] = new_course.key.id
    new_course["self"] = f"{request.host_url}courses/{new_course["id"]}"

    return (new_course, 201)

def get_access(payload):
    query = client.query(kind=USERS)
    results = list(query.fetch())
    for r in results:
        if r["sub"] == payload["sub"]:
            user = {
                "id": r.key.id,
                "role": r["role"]
            }
            return user
    return None

def validate_course_body(content):
    body = ["subject", "number", "title", "term", "instructor_id"]
    for item in body:
        if item not in content:
            return None

    instructor_key = client.key(USERS, content["instructor_id"])
    instructor = client.get(key=instructor_key)

    if instructor["role"] != "instructor":
        return None
    
    return content

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)