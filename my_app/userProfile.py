from flask import jsonify,session,request
from flask_httpauth import HTTPBasicAuth
from my_app import usersData,app
import secrets
import string

auth = HTTPBasicAuth()

def generate_random_key(length):
    characters = string.ascii_letters + string.digits
    random_key = ''.join(secrets.choice(characters) for _ in range(length))
    return random_key

app.secret_key = generate_random_key(64)

@auth.error_handler
def unauthorized():
    if auth.username != '':
        return jsonify({"error": "Error Code: 403. Incorrect password or username!"}), 403

    return jsonify({"error": "Error Code: 401. Unauthorized access, login required."}), 401

@auth.verify_password
def verify_password(username, password):
    if username in usersData and usersData[username]["PW"] == password:
        session['user'] = usersData[username]
        return True  # Authentication successful
    else:
        auth.username = username  # Store the username for use in the error handler
        if 'user' in session:
            session.pop('user')
        # print("verify_password",auth.current_user())
        return False  # Authentication failed

@app.route('/login', methods=['POST'],)
@auth.login_required
def login():
    return jsonify({"message": "Logged in successfully"})

@app.route('/logout', methods=['POST'],)
def logout():
    if 'user' in session:
        session.pop('user')
        return jsonify({"message": "Logged out"})
    else:
        return jsonify({"message": "You have not logged in"})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in usersData:
        return jsonify({"error": "Username already exists"}), 400

    usersData[username] = {"username": username, "PW": password, "Role": "User"},
    return jsonify({"message": "Registered successfully"})


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'user' in session :
            if session['user'].get('Role') == 'Admin':
                return func(*args, **kwargs)
            else:
                return jsonify({"error": "Error Code: 403. Unauthorized access. Admin role required."}), 403
        else:
            return jsonify({"error": "Error Code: 401. Unauthorized access. login required."}), 401
    return wrapper

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user' in session :
            return func(*args, **kwargs)
        else:
            return jsonify({"error": "Error Code: 401. Unauthorized access. login required."}), 401
    return wrapper


@app.route('/checkMyProfile', methods=['GET'],endpoint='checkMyProfile')
@login_required
def checkMyProfile():
    username = session['user'].get('username')
    return jsonify({'MyProfile': usersData[username]})

@app.route('/checkAllProfile', methods=['GET'],endpoint='checkAllProfile')
@admin_required
def checkAllProfile():
    return jsonify({'All Profiles': usersData})


@app.route('/changeMyProfile', methods=['PUT'],endpoint='changeMyProfile')
@login_required
def changeMyProfile():
    data = request.get_json()
    username = session['user'].get('username')

    if data.get("username"):
        if data.get("username") in usersData:
            return jsonify({"error": "Username already exists"}), 400
        usersData[data.get("username")] = {"username": data.get("username"),
                                           "PW": session['user'].get('PW'),
                                           "Role": session['user'].get('Role')}
        usersData.pop(username)
        session['user'] = usersData[data.get("username")]

    if data.get("password"):
        usersData[session['user'].get("username")] = {"username": data.get("username"),
                                           "PW": session['user'].get('PW'),
                                           "Role": session['user'].get('Role')}

        session['user'] = usersData[session['user'].get("username")]

    return jsonify({"message": "Your profile is updated."})

