from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user, fresh_login_required
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash 
import bleach

load_dotenv() #Reads from .env 
secret_key = os.getenv("SECRET_KEY")

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ZekeFinalBlog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours = 1)

db = SQLAlchemy(app)

class Blog(db.Model): # user.blog --> blogs  user.Author --> author
    BlogId = db.Column(db.Integer, primary_key = True)
    Book = db.Column(db.String(60), nullable = False)
    BookAuthor = db.Column(db.String(40), nullable = False)
    BlogTitle = db.Column(db.String(60), nullable = False)
    BlogAuthor = db.Column(db.String(40), nullable = False)
    InitialComment = db.Column(db.String(250), nullable = False)
    PostTime = db.Column(db.DateTime, default = datetime.now(timezone.utc))
    UserId = db.Column(db.Integer, db.ForeignKey('user.UserId'), nullable = False) # One-to-Many relationship where one user can have many blogs
    comments = db.relationship('Comment', backref = 'blog', lazy = True, cascade = 'all, delete-orphan')

class Comment(db.Model):
    CommentId = db.Column(db.Integer, primary_key = True)
    CommentText = db.Column(db.String(500), nullable = False)
    PostTime = db.Column(db.DateTime, default = datetime.now(timezone.utc))
    UserId = db.Column(db.Integer, db.ForeignKey('user.UserId'), nullable = False)
    BlogId = db.Column(db.Integer, db.ForeignKey('blog.BlogId'), nullable = False)

class User(db.Model, UserMixin): 
    UserId = db.Column(db.Integer, primary_key = True)
    UserName = db.Column(db.String(20), nullable = False, unique = True)
    Password = db.Column(db.String(200), nullable = False)
    Is_Admin = db.Column(db.Boolean, nullable=False) 
    blogs = db.relationship('Blog', backref = "author", lazy = True, cascade = 'all, delete-orphan') # backref Author refers to Blog author 
    comments = db.relationship('Comment', backref = 'author', lazy = True, cascade = 'all, delete-orphan')

    def get_id(self):
        return str(self.UserId)

with app.app_context():
    db.create_all()


login_manager = LoginManager() #part of flask_login; allows logins to work with code
login_manager.init_app(app) # Configure for login
login_manager.login_view = "login" # return to login if authentication fails
login_manager.refresh_view = "login" # This does the same as code above, but when session expires. Redundant.
login_manager.needs_refresh_message = "Your session has expired. Log in again. Or don't I guess."
login_manager.login_message = "Please log in or create an account." # Redirect to login_view define above

@login_manager.user_loader #Find correct user
def load_user(UserId): #Passing arbitrary argument
    #Database lookup logic to query for UserId
    return User.query.get(int(UserId)) # Could be user.UserId or only 'UserId' inside parameter.

def sanitize_comment(text):
    allowed_tags = ['p', 'br', 'strong', 'em',
                    'ul', 'ol', 'li', 'b', 'i', 'h1']
    
    bleached_text = bleach.clean(text, tags=allowed_tags, strip=True)
    return bleached_text

@app.cli.command()
def create_admin():
    import getpass

    #Make an admin from the CLI (command line)
    user_name = input("Enter admin username: ") 
    pass_word = getpass.getpass("Enter admin password: ") # Hide input in terminal
  
    admin = User(UserName=user_name.strip(), Password=generate_password_hash(pass_word.strip()), Is_Admin=True) 

    db.session.add(admin)
    db.session.commit()

    print(f"Admin user {user_name} initiated")

# Begin Routes

@app.route('/') # This route just points to the home route below it
def mainpage():
    return redirect(url_for("home"))

@app.route('/home') 
def home():
    return render_template("home.html")

@app.route('/admin')
@fresh_login_required #Sees if logged in and if session is fresh
def admin():
    blogs = Blog.query.all()
    users = User.query.all()
    return render_template("admin.html", blogs = blogs, users = users) # When making a list of the users, DON'T store in same name to avoid confusing Jinja

# @app.route('/admin/deleteUser/<int:id>', methods = ['POST'])
# @fresh_login_required
# def admin_deleteUser(id):
#     userDelete = User.query.get_or_404(id)

#     if (userDelete.Is_Admin):
#         flash("You cannot delete admin accounts here.")
#         return redirect(url_for('admin'))

#     db.session.delete(userDelete)
#     db.session.commit()
#     flash(f"Successfully deleted user \"{userDelete.UserName}\"")

#     return redirect(url_for('admin'))

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get("UserName").strip()
        password = request.form.get("Password").strip()
        confirmPassword = request.form.get("confirmPassword").strip()

        if len(username) < 2:
            flash("The username needs to be at least 2 characters!")
        elif len(password) < 8:
            flash("The password needs to be at least 8 characters!")
        elif not username:
            flash("This username is invalid! Re-enter the username.")
        elif not password:
            flash("This password is invalid! Re-enter a password.")
        elif password != confirmPassword:
            flash("The passwords do not match. Re-enter them.")
        else:
            username_taken = User.query.filter(User.UserName == username).first()
            if username_taken:
                flash("This username is taken, try another.")
            else:
                try:
                    new_user = User(UserName = username, Password = generate_password_hash(password), Is_Admin = False)
                    db.session.add(new_user)
                    db.session.commit()
                    flash("Sign up successful. Log in.")
                    return redirect(url_for('login')) # GO TO THE LOGIN PAGE and sign in with the credentials they just made. 
                except Exception as e: 
                    db.session.rollback()
                    signUpError = "There was an issue signing up, please try again."
                    return render_template('signup.html', signUpError = signUpError)
    
    return render_template('signup.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get("UserName").strip()
        password = request.form.get("Password").strip()

        userFound = User.query.filter(User.UserName == username).first() # Store the entered username as userFound here
        if userFound:
            if check_password_hash(userFound.Password, password): # hash the input and compare to hash stored on db.
                login_user(userFound, remember = False, fresh = True)
                return redirect(url_for('home'))
            else:
                flash("Wrong Password. Try again.")
                return render_template("login.html")

        else: 
            flash("This username doesn't exist. Re-enter it or sign up.") 
            return render_template("login.html")
        
    return render_template("login.html")

@app.route('/logout')
@login_required # Require login to take action or see page - In this case, the user cannot logout if they don't have an account
def logout():
    logout_user()
    return redirect(url_for('login')) 

@app.route('/home/createBlog', methods = ['GET', 'POST'])
@fresh_login_required # Check login status, check freshness of login
def home_createBlog():

    if request.method == "POST":
        blogTitle = request.form.get("BlogTitle").strip()
        initialComment = request.form.get("InitialComment").strip()
        bookTitle = request.form.get("Book").strip()
        bookAuthor = request.form.get("BookAuthor", "").strip() # Only input not required of the user

        if not blogTitle or not initialComment or not bookTitle:
            postError = "You must fill in all required fields!"
            return render_template('createBlog.html', postError = postError)
        
        try:
            new_blog = Blog(BlogTitle = blogTitle, 
                BlogAuthor = current_user.UserName, 
                InitialComment = initialComment, 
                Book = bookTitle,
                BookAuthor = bookAuthor, 
                UserId = current_user.UserId)
            db.session.add(new_blog)
            db.session.commit()
            flash("Tome added to blog collection successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            newBlogError = "There was an error creating your new blog. Try again." 
            return render_template("createBlog.html", newBlogError = newBlogError)
        
        # return render_template('postBlog.html', new_blog = new_blog)
        return redirect(url_for('home_blogs'))
    
    return render_template("createBlog.html")

@app.route('/home/blogs', methods = ['GET', 'POST'])
def home_blogs():
    blogs = Blog.query.all()
    return render_template('blogs.html', blogs = blogs)

@app.route('/home/blogs/<int:id>', methods = ['POST', 'GET']) # Use this to view each individual blog / Why is blogId not valid???
def home_selectBlogs(id):
    getBlog = Blog.query.get_or_404(id)
    return render_template('selectBlogs.html', getBlog = getBlog)

@app.route('/home/blogs/<int:blogId>/delete', methods = ['POST'])
@fresh_login_required
def home_selectBlogs_delete(blogId):
    blog_to_delete = Blog.query.get_or_404(blogId)

    if blog_to_delete.UserId != current_user.UserId and not current_user.Is_Admin:
        flash("You cannot delete this blog!")
        return redirect(url_for('home_selectBlogs', blogId = blogId))

    db.session.delete(blog_to_delete)
    db.session.commit()
    flash(f"Blog: \"{blog_to_delete.BlogTitle}\" deleted.")

    return redirect(url_for('home_blogs'))

@app.route('/home/blogs/<int:blogId>/comment', methods = ['POST'])
@fresh_login_required
def home_selectBlogs_comment(blogId):
    getBlog = Blog.query.get_or_404(blogId)

    commentText = request.form.get("CommentText").strip()

    if not commentText:
        inputError = "You cannot comment nothing."
        return render_template('selectBlogs.html', inputerror = inputError, blogId = blogId)
    
    squeaky_clean = sanitize_comment(commentText)
        
    try: 
        new_comment = Comment(
        CommentText = squeaky_clean, 
            UserId = current_user.UserId,
            BlogId = getBlog.BlogId 
            )
        db.session.add(new_comment)
        db.session.commit()
        flash("Commented successfully!")
    except Exception as e:
        db.session.rollback()
        print(f'Error: {e}')
        commentError = "There was an error posting your comment. Try again."
        return render_template('selectBlogs.html', commentError = commentError, blogId = blogId)
        
    return render_template('selectBlogs.html', getBlog = getBlog) # How to prevent recommenting on page reload.

@app.route('/home/blogs/<int:blogId>/comment/<int:commentId>/delete', methods = ['POST']) #Holding 2 IDs now, specify names.
@fresh_login_required
def home_selectBlogs_comment_delete(blogId, commentId):
    comment_to_delete = Comment.query.get_or_404(commentId)

    if comment_to_delete.UserId != current_user.UserId and not current_user.Is_Admin:
        flash("You cannot delete this comment!")
        return redirect(url_for('home_selectBlogs', id = blogId))
    
    username = comment_to_delete.author.UserName

    db.session.delete(comment_to_delete)
    db.session.commit()
    flash(f"Comment by {username} deleted.")

    return redirect(url_for('home_selectBlogs', id = blogId))

@app.route('/home/profile') 
@fresh_login_required 
def home_profile():
    return render_template("profile.html")

@app.route('/home/profile/delete/<int:userId>', methods = ['POST'])
@fresh_login_required
def home_profile_delete(userId):
    user_self_delete = User.query.get_or_404(userId)

    if current_user.Is_Admin: # Ensure admins cannot delete despite not being able to see button.
        flash("You cannot self delete an administrator account! Contact the owner.")
        return redirect(url_for('home_profile'))
    
    username = current_user.UserName # could also be: user_self_delete.UserName

    db.session.delete(user_self_delete)
    db.session.commit()
    flash(f"Deleted your account with username: {username}")

    return redirect(url_for('home')) # Does this produce an error since the user no longer exists?
    