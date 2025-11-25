from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from dotenv import load_dotenv


load_dotenv() #Reads from .env 

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ZekeFinalBlog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Blog(db.Model):
    BlogId = db.Column(db.Integer, primary_key = True)
    BlogTitle = db.Column(db.String(60), nullable = False)
    BlogAuthor = db.Column(db.String(40), nullable = False)
    post_time = db.Column(db.DateTime, default = datetime.now(timezone.utc))

class User(db.Model, UserMixin):
    UserId = db.Column(db.Integer, primary_key = True)
    UserName = db.Column(db.String(20), nullable = False, unique = True)
    Password = db.Column(db.String(20), nullable = False)

with app.app_context():
    db.create_all()

login_manager = LoginManager() #part of flask_login; allows logins to work with code
login_manager.login_view = "login" # return to login if authentication fails
login_manager.init_app(app) # Configure for login

login_manager.login_message = "To see this page, please log in or create an account."

@login_manager.user_loader #Find correct user
def load_user(UserId): #Passing arbitrary argument
    #Database lookup logic to query for UserId
    return User.get(UserId)

@app.route('/')
def mainpage():
    return redirect(url_for("home"))

@app.route('/home') #homepage refers to blog
def home():
    return render_template("home.html")

@app.route('/admin')
def admin():
    pass
    # return

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == "POST":
        UserName = request.form.get("UserName").strip()
        Password = request.form.get("Password").strip()
        confirmPassword = request.form.get("Password").strip()

        username_taken = User.query.filter_by(UserName = UserName)

        if username_taken:
            return "This username is taken, try another one."
        elif not UserName:
            return "This username is invalid! Re-enter a username."
        elif Password != confirmPassword:
            return "The passwords do not match. Re-enter them."
        elif not Password:
            return "This username is invallid! Re-enter a password."
        elif len(UserName) < 1: # username needs to be at least 3 characters, length starts at char 0.
            return "The Username needs to be longer!"
        elif len(Password) < 8: # password needs to be at least 10 characters
            return "The password needs to be longer!"
        else:
            try:
                new_user = User(UserName = UserName, Password = Password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember = False, fresh = True) # include the user object, remember after session expires? = NO, this is a fresh sign in.
                return redirect(url_for('login.html')) # GO TO THE LOGIN PAGE
            except Exception as e: 
                db.session.rollback()
                signUpError = "There was an issue signing up, please try again."
                return render_template('signup.html', signUpError = signUpError)
    
    return render_template('signup.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == "POSt":
        UserName = request.form.get("UserName").strip()
        Password = request.form.get("Password").strip()

        userFound = User.query.filter_by(UserName = UserName)
        if userFound:
            if User.Password == Password:
                login_user(userFound, remember = False, fresh = True)
                return redirect(url_for('home.html'))
            else:
                return "Wrong Password. Try again."
        else: 
            return "This username doesn't exist. Re-enter it or sign up."
        
    return render_template("login.html")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home.html')) # This is a guest, figure it out!
   
    


