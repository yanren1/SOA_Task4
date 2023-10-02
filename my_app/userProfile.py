from flask import jsonify,request
from flask_httpauth import HTTPBasicAuth
from my_app import usersData,app

auth = HTTPBasicAuth()

@auth.error_handler
def unauthorized():
    if auth.username != '':
        return jsonify({"error": "Error Code: 403. Incorrect password or username!"}), 403

    return jsonify({"error": "Error Code: 401. Unauthorized access, login required."}), 401

@auth.verify_password
def verify_password(username, password):
    if username in usersData and usersData[username]["PW"] == password:
        return True  # Authentication successful
    else:
        auth.username = username  # Store the username for use in the error handler

        return False  # Authentication failed

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in usersData:
        return jsonify({"error": "Username already exists"}), 400

    usersData[username] = {"username": username, "PW": password, "Role": "User"}
    return jsonify({"message": "Registered successfully"})


def admin_required(func):
    def wrapper(*args, **kwargs):
        username = auth.current_user()
        # print(username)
        if usersData[username]['Role'] == 'Admin':
            return func(*args, **kwargs)
        else:
            return jsonify({"error": "Error Code: 403. Unauthorized access. Admin role required."}), 403

    return wrapper

@app.route('/checkMyProfile', methods=['GET'],endpoint='checkMyProfile')
@auth.login_required
def checkMyProfile():
    username = auth.current_user()
    return jsonify({'MyProfile': usersData[username]})

@app.route('/checkAllProfile', methods=['GET'],endpoint='checkAllProfile')
@auth.login_required
@admin_required
def checkAllProfile():
    return jsonify({'All Profiles': usersData})

@app.route('/changeRole', methods=['PUT'],endpoint='changeRole')
@auth.login_required
@admin_required
def changeRole():
    data = request.get_json()
    if data.get("username") and data.get("username") in usersData:
        if data.get("username") == auth.current_user():
            return jsonify({'Warning': "Can't change your own role!"})
        if data.get("Role") and data.get("Role") in ["Admin", "User"]:
            usersData[data.get("username")]["Role"] = data.get("Role")
            return jsonify({'Message': f"User {data.get('username')} Role changed to {data.get('Role')}"})
        else:
            return jsonify({'Warning': "No valid role found!"})
    else:
        return jsonify({'Warning': "No valid username found!"})

@app.route('/changeMyProfile', methods=['PUT'],endpoint='changeMyProfile')
@auth.login_required
def changeMyProfile():
    data = request.get_json()
    username = auth.current_user()

    if data.get("username"):
        if data.get("username") in usersData:
            return jsonify({"error": "Username already exists"}), 400
        usersData[data.get("username")] = {"username": data.get("username"),
                                           "PW": usersData[username]['PW'],
                                           "Role": usersData[username]['Role']}
        usersData.pop(username)
        username = data.get("username")

    if data.get("password"):
        usersData[username] = {"username": username,
                                           "PW": data.get("password"),
                                           "Role": usersData[username]['Role']}


    return jsonify({"message": "Your profile is updated."})

