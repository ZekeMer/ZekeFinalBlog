from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from dotenv import load_dotenv
import os

load_dotenv() #Reads from .env 
secret_key = os.getenv("SECRET_KEY")

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ZekeFinalBlog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Blog(db.Model):
    BlogId = db.Column(db.Integer, primary_key = True)
    BlogTitle = db.Column(db.String(60), nullable = False)
    BlogAuthor = db.Column(db.String(40), nullable = False)
    PostTime = db.Column(db.DateTime, default = datetime.now(timezone.utc))
    Comment = db.Column(db.String(250), nullable = False)

class User(db.Model, UserMixin):
    UserId = db.Column(db.Integer, primary_key = True)
    UserName = db.Column(db.String(20), nullable = False, unique = True)
    Password = db.Column(db.String(20), nullable = False)

with app.app_context():
    db.create_all()

login_manager = LoginManager() #part of flask_login; allows logins to work with code
login_manager.login_view = "login" # return to login if authentication fails
login_manager.refresh_view = "login" # This does the same as code above, but when session expires. Redundant.
login_manager.init_app(app) # Configure for login

login_manager.login_message = "To see this page, please log in or create an account."

@login_manager.user_loader #Find correct user
def load_user(UserId): #Passing arbitrary argument
    #Database lookup logic to query for UserId
    return User.get(int(UserId))

@app.route('/') # This routejust points to the home route below it
def mainpage():
    return redirect(url_for("home"))

@app.route('/home') 
def home():
    return render_template("home.html")

@app.route('/admin') # HTML page for route to be added.
def admin():
    blog = Blog.query.all()
    user = User.query.all()
    return render_template("admin_home.html", blog = blog, user = user)

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
@login_required # Require login to take action or see page - In this case, the user cannot logout if they don't have an account
def logout():
    logout_user()
    return redirect(url_for('home.html')) # This is a guest, figure it out!

@app.route('/home/post') # This route marks the start of the site's actual pages.
def home_post():
    pass

@app.route('/home/profile') # Try to only show some routes, including this one, to logged on users
@login_required #If the user isn't logged in, then redirect ot login page specified earlier 
def home_profile():
    return render_template("profile.html")