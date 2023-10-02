from flask import jsonify, abort, url_for
from my_app import app, facultyData
from my_app.userProfile import auth,admin_required


# Get a list of all faculties
@app.route('/faculties', methods=['GET'],endpoint='get_faculties')
@auth.login_required
def get_faculties():
    faculty_info = []
    for faculty in facultyData:
        links = [{"rel": "self", "href": url_for('get_faculty', faculty=faculty, _external=True)},
                 {"rel": 'courses', 'href': url_for('get_faculty_courses', faculty=faculty, _external=True)},
                 # {"rel": 'students', 'href': url_for('get_faculty_students', faculty=faculty, _external=True)}
                 ]
        faculty_info.append({"faculty": faculty, "links": links})

    return jsonify({'faculties': faculty_info})


# Get details of a specific faculty
@app.route('/faculties/<string:faculty>', methods=['GET'],endpoint='get_faculty')
@auth.login_required
def get_faculty(faculty):
    links = [{"rel": "self", "href": url_for('get_faculty', faculty=faculty, _external=True)},
             {"rel": 'courses', 'href': url_for('get_faculty_courses', faculty=faculty, _external=True)},
             {"rel": 'students', 'href': url_for('get_faculty_students', faculty=faculty, _external=True)}]

    for student_id in facultyData[faculty]['Students']:
        links.append({"rel": "student", "href": url_for('get_student', student_id=student_id, _external=True)})
    return jsonify({'faculty': faculty, 'links': links})


# Get details of a student's registered course
@app.route('/faculties/<string:faculty>/courses', methods=['GET'],endpoint='get_faculty_courses')
@auth.login_required
def get_faculty_courses(faculty):
    if faculty not in facultyData:
        abort(404)
    return jsonify(
        {'courses': facultyData[faculty]['Courses'], 'links': [{"rel": "self", "href": url_for('get_faculty_courses',
                                                                                               faculty=faculty,
                                                                                               _external=True)}]})


# Get students by faculty
@app.route('/faculties/<string:faculty>/students', methods=['GET'],endpoint='get_faculty_students')
@auth.login_required
@admin_required
def get_faculty_students(faculty):
    for student_id in facultyData[faculty]['Students']:
        facultyData[faculty]['Students'][student_id]['links'] = [
            {"rel": "self", "href": url_for('get_student', student_id=student_id, _external=True)}]

    return jsonify(
        {'Students': facultyData[faculty]['Students'], 'links': [{"rel": "self", "href": url_for('get_faculty_students',
                                                                                                 faculty=faculty,
                                                                                                 _external=True)}]})
