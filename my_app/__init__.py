# __init__.py
from flask import Flask
import random

app = Flask(__name__)

# sample data
nameList = ['Alice', 'Bob', 'Eva', 'John', 'Ryan', 'James', 'Robert', 'Michael', 'David', 'William', 'Richard',
            'Joseph']
countryList = ['USA', 'Canada', 'UK', 'China', 'Finland']

facultyList = ['Humanities and Social Sciences', 'Information Technology', 'Education and Psychology',
               'Sport and Health Sciences', 'Mathematics and Science', 'Business and Economics']
profList = ['Prof A', 'Prof B', 'Prof C', 'Prof D', 'Prof E', 'Prof F', 'Prof G']
courseIds = [101, 201, 301, 401]

coursesData = {''.join([char for char in faculty if char.isupper()]) + str(courseId):
                   {'Course Name': faculty + ' ' + str(courseId),
                    'Faculty': faculty,
                    'Responsible Teacher': random.choice(profList),
                    'Credits': random.randint(0, 6)}
               for faculty in facultyList for courseId in courseIds}

studentData = {index: {'Name': name, 'Age': random.randint(18, 40), 'Country': random.choice(countryList),
                       'Faculty': random.choice(facultyList),
                       'Course Registered': {courseId: {'Course Name': coursesData[courseId]['Course Name']}
                                             for courseId in
                                             random.sample(list(coursesData.keys()), random.randint(1, 3))}
                       } for index, name in enumerate(nameList)}

facultyData = {faculty: {'Students': {k: v for k, v in studentData.items() if v['Faculty'] == faculty},
                         'Courses': {k: v for k, v in coursesData.items() if
                                     ''.join([char for char in faculty if char.isupper()]) in k}
                         } for faculty in facultyList}

usersData = {
    "user1": {"username":"user1","PW":"123","Role":"Admin"},
    "user2": {"username":"user2","PW":"321","Role":"User"}
}

