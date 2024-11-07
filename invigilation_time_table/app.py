from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash

from flask import send_file
from io import BytesIO
from flask_pymongo import PyMongo
import secrets
import string
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson.objectid import ObjectId
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key


app.config["MONGO_URI"] = "mongodb://localhost:27017/time_table_data"  

mongo = PyMongo(app)

availability_collection = mongo.db.availability

@app.template_filter()
def zip_filter(*args):
    return zip(*args)


# Sample user data
users = {
    "admin": {"password": "admin123", "role": "admin"},
    
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    if role not in ['admin', 'user']:
        flash("Invalid role specified!")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if role == "admin":
            # Check login credentials for admin
            admin_user = users.get(username)
            if admin_user and admin_user['password'] == password:
                session['username'] = username
                session['role'] = role
                flash("Logged in as admin!")
                return redirect(url_for('dashboard', role=role))
            else:
                flash("Invalid admin credentials!")
        else:
            # Check login credentials for users from MongoDB
            user = mongo.db.faculty.find_one({"email": username})  # Removed role check here
            if user:
                if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    session['username'] = user['name']
                    session['role'] = role
                    flash("Logged in as user!")
                    return redirect(url_for('dashboard', role=role))
                else:
                    flash("Invalid password for user!")
            else:
                flash("User not found!")

    return render_template('login.html', role=role)

@app.route('/dashboard/<role>')
def dashboard(role):
    if 'username' not in session or session.get('role') != role:
        flash("You must log in first!")
        return redirect(url_for('index'))

    # Render admin_dashboard for admins, faculty_dashboard for users
    if role == 'admin':
        template = 'admin_dashboard.html'
    elif role == 'user':
        template = 'faculty_dashboard.html'
    else:
        flash("Invalid role!")
        return redirect(url_for('index'))

    return render_template(template, role=role, username=session['username'])

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash("You must log in first!")
        return redirect(url_for('index'))
    
    # Sample data for the profile page (replace with database/user data as needed)
    profile_info = {
        "username": session['username'],
        "role": session['role'],
        "email": "admin@example.com",
        "avatar_url": "https://via.placeholder.com/150"  # Replace with actual avatar URL or file
    }
    
    return render_template('admin_profile.html', profile_info=profile_info)


# Route for the add faculty page
@app.route('/add_faculty')
def add_faculty():
    return render_template('add_faculty.html')


@app.route('/submit_faculty', methods=['POST'])
def submit_faculty():
    # Generate a random password
    password_length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(secrets.choice(characters) for _ in range(password_length))

    # Get form data
    faculty_data = {
        "name": request.form['name'],
        "designation": request.form['designation'],
        "contact_number": request.form['contact_number'],
        "subject": request.form['subject'],
        "email": request.form['email'],
        "password": random_password,  # Store the random password
        "address": request.form['address']
    }

    # Hash the password before storing it in MongoDB
    hashed_password = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt())
    faculty_data["password"] = hashed_password  # Replace the plain password with hashed password

    # Check if email or contact number already exists
    existing_faculty = mongo.db.faculty.find_one({
        "$or": [
            {"email": faculty_data["email"]},
            {"contact_number": faculty_data["contact_number"]}
        ]
    })

    if existing_faculty:
        flash("Email or Contact Number already exists!")
        return redirect(url_for('add_faculty'))

    # Insert data into MongoDB
    mongo.db.faculty.insert_one(faculty_data)

    # Send email with the random password
    send_email(faculty_data["email"], random_password)

    # Redirect to success page
    return render_template('faculty_added.html', role='admin', random_password=random_password)

def send_email(to_email, random_password):
    from_email = "mannesrija03@gmail.com"  # Replace with your email
    from_password = "tndhsdsnrfsnrfcz"  # Replace with your email password or app password

    subject = "Your Faculty Account Password"
    body = f"Hello,\n\nYour account has been created successfully.\nYour random password is: {random_password}\n\nPlease keep this password secure."

    # Create a multipart email message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the email body to the message
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Create a secure SSL context and send the email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(from_email, from_password)  # Log in to your email account
            server.send_message(msg)  # Send the email
    except Exception as e:
        print(f"Error sending email: {e}")  # Print any error message
        
@app.route('/update_faculty', methods=['GET', 'POST'])
def update_faculty():
    if request.method == 'POST':
        # Handle the faculty update as previously defined
        faculty_email = request.form['email']
        faculty_data = {
            "name": request.form['name'],
            "designation": request.form['designation'],
            "contact_number": request.form['contact_number'],
            "subject": request.form['subject'],
            "address": request.form['address'],
            "email": faculty_email
        }

        # Check if password is being updated
        new_password = request.form.get('password')
        if new_password:
            # Hash the new password before updating
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            faculty_data["password"] = hashed_password
            # Send the new password to the faculty's email
            send_email(faculty_email, new_password)

        # Update the faculty details in the database
        mongo.db.faculty.update_one({"email": faculty_email}, {"$set": faculty_data})

        flash("Faculty details updated successfully!")
        return redirect(url_for('update_faculty'))  # Redirect to the same page to see updated list

    # GET request - fetch all faculty members
    faculty_list = mongo.db.faculty.find()  # Fetch all faculty members

    return render_template('update_faculty.html', faculty_list=faculty_list)  # Pass the faculty list to the template



@app.route('/edit_faculty/<email>', methods=['GET', 'POST'])
def edit_faculty(email):
    faculty = mongo.db.faculty.find_one({"email": email})

    if request.method == 'POST':
        # Collect data from the form
        faculty_data = {
            "name": request.form['name'],
            "designation": request.form['designation'],
            "contact_number": request.form['contact_number'],
            "subject": request.form['subject'],
            "address": request.form['address'],
            "email": email  # Keep the email as it is
        }

        # Check if a new password is provided
        new_password = request.form.get('password')
        if new_password:
            # Hash the new password before updating
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            faculty_data["password"] = hashed_password
            # Send the new password to the faculty's email
            send_email(email, new_password)

        # Update the faculty details in the database
        mongo.db.faculty.update_one({"email": email}, {"$set": faculty_data})

        flash("Faculty details updated successfully!")
        return redirect(url_for('update_faculty'))  # Redirect to the faculty list

    return render_template('edit_faculty.html', faculty=faculty)




@app.route('/add_notification')
def add_notification():
    return render_template('add_notification.html')

@app.route('/download_notification_format')
def download_notification_format():
    # Create a DataFrame with the specified columns
    columns = ['Date', 'Civil', 'EEE', 'Mech', 'ECE', 'CSE', 'EIE', 'IT', 'ET', 'H&S']
    df = pd.DataFrame(columns=columns)

    # Save the DataFrame to an Excel file
    file_path = 'notification_format.xlsx'
    df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True)

@app.route('/upload_notification', methods=['POST'])
def upload_notification():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Check the file extension
    if not (file.filename.endswith('.xls') or file.filename.endswith('.xlsx') or file.filename.endswith('.csv')):
        return jsonify({'message': 'Invalid file format. Please upload Excel or CSV files.'}), 400

    # Read the file into a DataFrame
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:  # For .xls or .xlsx
            df = pd.read_excel(file)

        # Convert DataFrame to a list of dictionaries for MongoDB
        notification_data = df.to_dict(orient='records')

        # Insert data into MongoDB
        mongo.db.notifications.insert_many(notification_data)

        return jsonify({'message': 'Notifications uploaded successfully!'}), 200
    except Exception as e:
        print(f"Error processing file: {e}")
        return jsonify({'message': 'An error occurred while processing the file'}), 500
    

@app.route('/update_notification')
def update_notification():
    notifications_data = mongo.db.notifications.find()  # Fetch all notification entries from MongoDB
    return render_template('update_notification.html', notifications_data=notifications_data)


@app.route('/delete_notification/<notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    result = mongo.db.notifications.delete_one({'_id': ObjectId(notification_id)})
    if result.deleted_count > 0:
        return jsonify({'message': 'Notification deleted successfully!'}), 200
    else:
        return jsonify({'message': 'Notification not found!'}), 404

@app.route('/schedule_examination')
def schedule_examination():
    return render_template('schedule_examination.html')

# Route to handle file upload
@app.route('/upload_schedule', methods=['POST'])
def upload_schedule():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Check the file extension
    if not (file.filename.endswith('.xls') or file.filename.endswith('.xlsx') or file.filename.endswith('.csv')):
        return jsonify({'message': 'Invalid file format. Please upload Excel or CSV files.'}), 400

    # Read the file into a DataFrame
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        else:  # For .xls or .xlsx
            df = pd.read_excel(file)

        # Retrieve additional data from the form
        exam_start_date = request.form.get('exam_start_date')
        exam_end_date = request.form.get('exam_end_date')
        exam_time = request.form.get('exam_time')

        # Convert DataFrame to a list of dictionaries for MongoDB
        schedule_data = df.to_dict(orient='records')

        # Add additional data to each schedule entry
        for entry in schedule_data:
            entry['exam_start_date'] = exam_start_date
            entry['exam_end_date'] = exam_end_date
            entry['exam_time'] = exam_time

        # Insert data into MongoDB
        mongo.db.schedule.insert_many(schedule_data)

        return jsonify({'message': 'Schedule uploaded successfully!'}), 200
    except Exception as e:
        print(f"Error processing file: {e}")
        return jsonify({'message': 'An error occurred while processing the file'}), 500
    
    
@app.route('/download_schedule_format')
def download_schedule_format():
    # Create a sample DataFrame
    data = {
        'College Name': ['Your College Name'] * 6,
        'Branch Name': ['Branch A', 'Branch B', 'Branch C', 'Branch D', 'Branch E', 'Branch F'],
        'Department': ['Department A', 'Department B', 'Department C', 'Department D', 'Department E', 'Department F'],
        'Day': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
        'From Date': ['2024-11-06'] * 6,
        'To Date': ['2024-11-12'] * 6,
        'Timing': ['10:00 AM - 12:00 PM', '1:00 PM - 3:00 PM', '10:00 AM - 12:00 PM', '1:00 PM - 3:00 PM', '10:00 AM - 12:00 PM', '1:00 PM - 3:00 PM'],
    }
    
    df = pd.DataFrame(data)

    # Save the DataFrame to an Excel file in memory
    output = BytesIO()
    df.to_excel(output, index=False, sheet_name='Examination Schedule')
    output.seek(0)

    # Send the file as a download
    return send_file(output, as_attachment=True, download_name='examination_schedule_format.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/update_examination')
def update_examination():
    schedule_data = list(mongo.db.schedule.find())  # Fetch all schedule entries from MongoDB and convert to list
    return render_template('update_examination.html', schedule_data=schedule_data)

@app.route('/delete_schedule/<schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    result = mongo.db.schedule.delete_one({'_id': ObjectId(schedule_id)})
    if result.deleted_count > 0:
        return jsonify({'message': 'Schedule deleted successfully!'}), 200
    else:
        return jsonify({'message': 'Schedule not found!'}), 404



@app.route('/assign_faculty')
def assign_faculty_page():
    schedule_data = list(mongo.db.schedule.find())  # Fetch schedule data
    faculty_list = list(mongo.db.faculty.find())    # Fetch all faculty names
    return render_template('assign_faculty.html', schedule_data=schedule_data, faculty_list=faculty_list)


@app.route('/assign_faculty', methods=['POST'])
def assign_faculty():
    # Assign faculty to each schedule item based on submitted form data
    for key, value in request.form.items():
        if key.startswith('faculty_'):
            schedule_id = key.split('_')[1]  # Extract the ObjectId from the form key
            faculty_name = value
            
            # Update the schedule in MongoDB to assign the selected faculty member
            mongo.db.schedule.update_one(
                {'_id': ObjectId(schedule_id)},
                {'$set': {'assigned_faculty': faculty_name}}
            )
    
    return jsonify({'message': 'Faculty assigned successfully!'}), 200


@app.route('/assigned_faculty')
def assigned_faculty_page():
    # Fetch all schedule entries with assigned faculty from MongoDB
    schedule_data = list(mongo.db.schedule.find({"assigned_faculty": {"$exists": True}}))
    return render_template('assigned_faculty.html', schedule_data=schedule_data)

@app.route('/delete_assigned_faculty/<schedule_id>', methods=['DELETE'])
def delete_assigned_faculty(schedule_id):
    # Remove the assigned faculty from the schedule
    mongo.db.schedule.update_one(
        {'_id': ObjectId(schedule_id)},
        {'$unset': {'assigned_faculty': ""}}  # Remove the assigned faculty field
    )
    return jsonify({'message': 'Assigned faculty deleted successfully!'}), 200

@app.route('/available_faculty')
def available_faculty():
    # Fetch all records from the 'availability' collection
    faculty_availability = availability_collection.find()

    # Pass the data to the template as a list of dictionaries
    return render_template('available_faculty.html', faculty_availability=faculty_availability)


@app.route('/add_timetable', methods=['GET', 'POST'])
def add_timetable():
    if request.method == 'POST':
        # Fetch data from the form
        faculty_name = request.form.get('faculty_name')  # Get the selected faculty name from the form
        selected_date = request.form.get('date')  # Get the selected date from the form

        # Fetch the faculty member's document from the database using their name
        faculty = mongo.db.faculty.find_one({"name": faculty_name})
        
        if faculty:
            timetable_data = {
                "faculty_id": faculty['_id'],  # Use the faculty's ObjectId
                "faculty_name": faculty['name'],  # Store the faculty's name
                "faculty_email": faculty['email'],  # Store the faculty's email
                "date": selected_date,  # Add the selected date
                "monday": {
                    "subject": request.form.getlist('monday[subject][]'),
                    "from": request.form.getlist('monday[from][]'),
                    "to": request.form.getlist('monday[to][]')
                },
                "tuesday": {
                    "subject": request.form.getlist('tuesday[subject][]'),
                    "from": request.form.getlist('tuesday[from][]'),
                    "to": request.form.getlist('tuesday[to][]')
                },
                "wednesday": {
                    "subject": request.form.getlist('wednesday[subject][]'),
                    "from": request.form.getlist('wednesday[from][]'),
                    "to": request.form.getlist('wednesday[to][]')
                },
                "thursday": {
                    "subject": request.form.getlist('thursday[subject][]'),
                    "from": request.form.getlist('thursday[from][]'),
                    "to": request.form.getlist('thursday[to][]')
                },
                "friday": {
                    "subject": request.form.getlist('friday[subject][]'),
                    "from": request.form.getlist('friday[from][]'),
                    "to": request.form.getlist('friday[to][]')
                },
                "saturday": {
                    "subject": request.form.getlist('saturday[subject][]'),
                    "from": request.form.getlist('saturday[from][]'),
                    "to": request.form.getlist('saturday[to][]')
                },
            }

            # Store timetable in MongoDB
            mongo.db.timetables.insert_one(timetable_data)

            # Flash message for success
            flash('Timetable added successfully!', 'success')
        else:
            flash('Faculty member not found.', 'danger')

        return redirect(url_for('add_timetable'))  # Redirect back to the add timetable page

    # Fetch all faculty members from MongoDB
    faculty_list = mongo.db.faculty.find()
    return render_template('add_timetable.html', faculty_list=faculty_list)





@app.route('/update_timetable', methods=['GET', 'POST'])
def update_timetable():
    if request.method == 'POST':
        timetable_id = request.form.get('timetable_id')
        faculty_name = request.form.get('faculty_name')  # Get the faculty name from the form
        selected_date = request.form.get('date')

        # Fetch the faculty's ID based on the name
        faculty = mongo.db.faculty.find_one({"name": faculty_name})
        faculty_id = faculty["_id"] if faculty else None

        timetable_data = {
            "faculty_id": faculty_id,  # Use the fetched faculty_id
            "date": selected_date,
            "monday": {
                "subject": request.form.getlist('monday[subject][]'),
                "from": request.form.getlist('monday[from][]'),
                "to": request.form.getlist('monday[to][]')
            },
            "tuesday": {
                "subject": request.form.getlist('tuesday[subject][]'),
                "from": request.form.getlist('tuesday[from][]'),
                "to": request.form.getlist('tuesday[to][]')
            },
            "wednesday": {
                "subject": request.form.getlist('wednesday[subject][]'),
                "from": request.form.getlist('wednesday[from][]'),
                "to": request.form.getlist('wednesday[to][]')
            },
            "thursday": {
                "subject": request.form.getlist('thursday[subject][]'),
                "from": request.form.getlist('thursday[from][]'),
                "to": request.form.getlist('thursday[to][]')
            },
            "friday": {
                "subject": request.form.getlist('friday[subject][]'),
                "from": request.form.getlist('friday[from][]'),
                "to": request.form.getlist('friday[to][]')
            },
            "saturday": {
                "subject": request.form.getlist('saturday[subject][]'),
                "from": request.form.getlist('saturday[from][]'),
                "to": request.form.getlist('saturday[to][]')
            },
        }

        # Update timetable in MongoDB
        mongo.db.timetables.update_one({"_id": ObjectId(timetable_id)}, {"$set": timetable_data})

        # Flash message for success
        flash('Timetable updated successfully!', 'success')

        return redirect(url_for('update_timetable'))  # Redirect back to the update timetable page

    # Fetch all timetables from MongoDB
    timetables = mongo.db.timetables.find()
    
    # Fetch all faculty members to populate the faculty dropdown
    faculty_list = mongo.db.faculty.find()

    return render_template('update_timetable.html', timetables=timetables, faculty_list=faculty_list)



@app.route('/get_timetable_details/<timetable_id>')
def get_timetable_details(timetable_id):
    timetable = mongo.db.timetables.find_one({"_id": ObjectId(timetable_id)})
    
    if timetable:
        # Convert ObjectId to string for JSON serialization
        timetable['_id'] = str(timetable['_id'])  # Convert ObjectId to string
        
        # Convert faculty_id if it exists and is an ObjectId
        if 'faculty_id' in timetable:
            faculty_id = timetable['faculty_id']
            timetable['faculty_id'] = str(faculty_id)  # Convert faculty_id to string
            
            # Fetch faculty using faculty_id
            faculty = mongo.db.faculty.find_one({"_id": faculty_id})
            timetable['faculty_name'] = faculty['name'] if faculty else None  # Add faculty name to timetable
        
        # Convert other ObjectId fields if they exist (add more fields as necessary)
        for key in timetable:
            if isinstance(timetable[key], ObjectId):
                timetable[key] = str(timetable[key])
        
        return jsonify(timetable)  # Convert the timetable document to JSON
    else:
        return jsonify({"error": "Timetable not found"}), 404
    
    
@app.route('/view_timetable', methods=['GET'])
def view_timetable():
    if 'username' not in session:
        flash("You must log in first!")
        return redirect(url_for('index'))

    # Get the search parameters from the request
    faculty_name = request.args.get('faculty_name')
    date = request.args.get('date')

    # Build the filter query
    filter_query = {}
    if faculty_name:
        filter_query['faculty_name'] = {'$regex': faculty_name, '$options': 'i'}  # Case-insensitive search
    if date:
        filter_query['date'] = date

    # Fetch timetable entries from MongoDB based on the filter
    timetables = list(mongo.db.timetables.find(filter_query))

    return render_template('view_timetable.html', timetables=timetables)




@app.route('/faculty_dashboard', methods=['GET'])
def faculty_dashboard():
    faculty_id = session.get('faculty_id')
    faculty = mongo.db.faculty.find_one({"_id": ObjectId(faculty_id)})

    if not faculty:
        print("Faculty not found for ID:", faculty_id)  # Debug statement
        return "Faculty not found", 404

    # Fetch all faculty names for the dropdown
    all_faculty = list(mongo.db.faculty.find({}))
    print("All faculty members:", all_faculty)  # Debug statement

    return render_template('faculty_dashboard.html', username=faculty['name'], faculty_id=faculty_id, all_faculty=all_faculty)





@app.route('/post_availability', methods=['POST'])
def post_availability():
    """Route to post faculty availability information to MongoDB."""
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    # Validate required fields
    required_fields = ['name', 'email', 'contactNumber', 'branch', 'designation', 'availabilityDate', 'availableTime']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    # Insert into MongoDB
    try:
        availability_collection.insert_one(data)
        return jsonify({'message': 'Availability posted successfully!'}), 200
    except Exception as e:
        print(f"Error inserting data: {e}")
        return jsonify({'message': 'An error occurred while saving data'}), 500



@app.route('/examination_schedule')
def examination_schedule_page():
    schedule_data = list(mongo.db.schedule.find())  # Fetch all schedule entries from MongoDB and convert to list
    return render_template('examination_schedule.html', schedule_data=schedule_data)

@app.route('/scheduled_message')
def scheduled_message_page():
    # Fetch all schedule entries with assigned faculty from MongoDB
    schedule_data = list(mongo.db.schedule.find({"assigned_faculty": {"$exists": True}}))
    return render_template('scheduled_message.html', schedule_data=schedule_data)
    
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash("Logged out successfully!")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
