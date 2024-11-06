import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import inputScript
import sqlite3
from socialmedia import social  # Import the social function

# Load models and vectorizer
model1 = pickle.load(open('phishing.pkl', 'rb'))  # Phishing detection model
model2 = pickle.load(open('phishmsg.pkl', 'rb'))       # Email spam detection

# api_key
api_key = "AIzaSyDuyr0kocEYAJjgwj8xPT07VLh8vpzExc4"

# Load and preprocess email data for feature extraction
raw_mail = pd.read_csv("Phishing_Email.csv")
mail_data = raw_mail.where((pd.notnull(raw_mail)), '')
mail_data.loc[mail_data['Email Type'] == 'Safe Email', 'category'] = 0
mail_data.loc[mail_data['Email Type'] == 'Phishing Email', 'category'] = 1
X = mail_data['Email Text']
Y = mail_data['Email Type']
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=3)

feature_extraction = TfidfVectorizer(min_df=1, stop_words='english', lowercase=True)
feature_extraction.fit(X_train)

app = Flask(__name__, template_folder='templates')


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/index')
def home():
    return render_template('index.html')


# Database code
def init_db():
    conn = sqlite3.connect('database.db')  # Connect to SQLite database (or create it)
    cursor = conn.cursor()
    # Create a table to store user experiences
    cursor.execute('''CREATE TABLE IF NOT EXISTS experiences (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        userstory TEXT NOT NULL
                     )''')
    conn.commit()  # Save the changes
    conn.close()   # Close the connection

# Call init_db() when the application starts to set up the database
init_db()

# Route to display the form for submitting experiences
@app.route('/experience')
def experience_form():
    return render_template('experience.html')


# Route to handle the form submission
@app.route('/submit_experience', methods=['POST'])
def submit_experience():
    username = request.form['username']  # Get the username from the form
    userstory = request.form['userstory']  # Get the user story from the form
    
    # Connect to the database and insert the new experience
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO experiences (username, userstory) VALUES (?, ?)", (username, userstory))
    conn.commit()  # Save the new entry to the database
    conn.close()   # Close the connection
    
    # Redirect the user to the view page to see all experiences
    return redirect(url_for('view_experiences'))


# Route to display all submitted experiences
@app.route('/viewexperience')
def view_experiences():
    # Connect to the database and fetch all experiences
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, userstory FROM experiences")
    experiences = cursor.fetchall()  # Get all records as a list of tuples
    conn.close()
    
    # Render the viewexperience.html page with the fetched experiences
    return render_template('viewexperience.html', experiences=experiences)


# URL phishing prediction
@app.route('/predict', methods=['GET', 'POST'])
def predict_phishing():
    if request.method == 'POST':
        url = request.form.get('URL')
        if not url:
            return render_template('predict.html', prediction="Error: URL is required")
        
        # Call the social function
        social_result = social(api_key, url)
        
        try:
            checkprediction = inputScript.Phishing_Website_Detection(url)
            checkprediction = np.array(checkprediction).reshape(1, -1)
            prediction = model1.predict(checkprediction)
            output = prediction[0]
            
            if output == 1:
                pred = "Safe! This is a Legitimate Website."
            else:
                pred = "Suspicious. Be cautious!"

            # Handle the result from the social function
            if "safe" in social_result:
                social_status = social_result  # Contains safety status
            else:
                social_status = social_result  # Contains social media link status

            return render_template('predict.html', prediction=pred, social_status=social_status, url="The URL is: " + url)
        
        except ValueError as e:
            return render_template('predict.html', prediction="Please enter a full URL, including the path (e.g., https://example.com/path).") if "features" in str(e) else print(f"An error occurred: {e}")
        except Exception as e:
            return render_template('predict.html', prediction='An error occurred: {}'.format(e), url="The URL is: " + url)
    else:
        return render_template('predict.html', prediction='Error: Invalid request method')


# Email phishing prediction
@app.route('/sendd', methods=['POST'])
def predict_email():
    a = request.form.get('mail_check')
    c = request.form.get('out_type')

    if not a:
        return "Enter some value of mail"
    if c is None:
        return "Select the output type"

    input_mail = [a]
    input_mail = feature_extraction.transform(input_mail)
    result = model2.predict(input_mail)

    if c == "Json_format":
        status = "Warning! It's a spam message." if result[0] == 0 else "It's a safe message."
        return jsonify({"Message": a, "Ans_format": c, "Status": status})

    return render_template('predict1.html', label=result[0], message=a)


@app.route('/predict_api', methods=['POST'])
def predict_api():
    try:
        data = request.get_json(force=True)
        if not data:
            raise ValueError("Invalid JSON data")
        input_array = np.array(list(data.values()))
        input_array = input_array.reshape(1, -1)
        prediction = model1.predict(input_array)
        output = prediction[0]
        return jsonify({'output': output})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
