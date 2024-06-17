import pathlib
import os
from flask import Flask, session, redirect, url_for, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from PIL import Image
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = pathlib.Path(app.config['UPLOAD_FOLDER'])
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create the upload folder if it doesn't exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

db = SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200), nullable=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('likes', lazy=True))
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))

class Dislike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('dislikes', lazy=True))
    post = db.relationship('Post', backref=db.backref('dislikes', lazy=True))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    post = db.relationship('Post', backref=db.backref('comments', lazy=True))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('favorites', lazy=True))
    post = db.relationship('Post', backref=db.backref('favorites', lazy=True))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # "like", "comment", or "dislike"
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    post = db.relationship('Post', backref=db.backref('notifications', lazy=True))


def protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def posts():
    try:
        queryset = Post.query.all()
        return render_template("post.html", queryset=queryset)
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/posts", methods=["POST"])
@protected
def add_post():
    try:
        content = request.form["content"]
        user_id = session['user']['id']
        post = Post(content=content, user_id=user_id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))
    
@app.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
@protected
def edit_post(post_id):
    try:
        post = Post.query.get(post_id)
        if not post:
            return redirect(url_for("error", message="Post not found."))

        if session['user']['id'] != post.user_id:
            return redirect(url_for("error", message="You are not authorized to edit this post."))

        if request.method == "POST":
            content = request.form['content']
            post.content = content
            db.session.commit()
            return redirect(url_for("posts"))

        return render_template("edit_post.html", post=post)
    except Exception as e:
        return render_template("error.html", message=str(e))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]
            role = request.form["role"]
            admin_code = request.form.get("admin_code", "")

            if not username or not password or not confirm_password:
                raise ValueError("Username, password, and password confirmation are required.")

            if password != confirm_password:
                raise ValueError("Passwords do not match.")

            if len(password) < 6:
                raise ValueError("Password must be at least 6 characters long.")
            
            if len(username) > 12:
                raise ValueError("Username must not be more than 12 characters long.")
            
            if len(username) < 6:
                raise ValueError("Username must me at least 6 charcters long.")
            
            if len(password) > 12:
                raise ValueError("Password must not be more than 12 characters long.")

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                raise ValueError("Username already exists.")

            if role == "Admin" and admin_code != "1112":
                raise ValueError("Invalid admin code.")

            hashed_password = generate_password_hash(password)
            is_admin = role == "Admin" and admin_code == "1111"
            profile_picture = 'static/pfp.png'  # Default profile picture filename
            user = User(username=username, password=hashed_password, is_admin=is_admin, profile_picture=profile_picture)
            db.session.add(user)
            db.session.commit()

            return redirect(url_for("login"))
        except Exception as e:
            return render_template("register.html", message=str(e))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            user = User.query.filter_by(username=username).first()
            
            if not user or not check_password_hash(user.password, password):
                flash("Invalid username or password. Please try again.", "error")
                return redirect(url_for("login"))

            session['user'] = {'id': user.id, "is_admin": user.is_admin} 
            session.modified = True
            return redirect(url_for("posts"))
        except Exception as e:
            return render_template("error.html", message=str(e))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("posts"))

@app.route("/error")
def error():
    error_message = request.args.get('message', 'An error occurred.')
    return render_template("error.html", message=error_message)

@app.route("/posts/<int:post_id>/delete", methods=["POST"])
@protected
def delete_post(post_id):
    try:
        # Retrieve the post
        post = Post.query.get(post_id)
        if not post:
            app.logger.debug(f"Post with ID {post_id} not found.")
            return redirect(url_for("error", message="Post not found."))
        
        # Check if the current user is the owner of the post
        if session['user']['id'] != post.user_id:
            app.logger.debug(f"User {session['user']['id']} is not authorized to delete post {post_id}.")
            return redirect(url_for("error", message="You are not authorized to delete this post."))
        
        # Delete likes and dislikes associated with the post
        likes = Like.query.filter_by(post_id=post_id).all()
        for like in likes:
            db.session.delete(like)
        
        dislikes = Dislike.query.filter_by(post_id=post_id).all()
        for dislike in dislikes:
            db.session.delete(dislike)
        
        # Delete the post
        db.session.delete(post)
        db.session.commit()
        
        app.logger.debug(f"Post {post_id} deleted successfully.")
        return redirect(url_for("posts"))
    except Exception as e:
        app.logger.error(f"Error deleting post {post_id}: {str(e)}")
        return render_template("error.html", message="An error occurred while trying to delete the post.")


@app.route("/profile")
@protected
def profile():
    try:
        user_id = session['user']['id']
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for("error", message="User not found."))
        return render_template("profile.html", user=user)
    except Exception as e:
        return render_template("error.html", message=str(e))
    
@app.route("/edit_profile", methods=["GET", "POST"])
@protected
def edit_profile():
    user_id = session['user']['id']
    user = User.query.get(user_id)
    if request.method == "POST":
        try:
            new_username = request.form["username"]
            new_password = request.form["password"]
            
            if not new_username:
                raise ValueError("Username cannot be empty.")
            
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != user_id:
                raise ValueError("Username already exists.")
            
            user.username = new_username
            if new_password:
                user.password = generate_password_hash(new_password)
            
            db.session.commit()
            return redirect(url_for("profile"))
        except Exception as e:
            return render_template("error.html", message=str(e))
    return render_template("edit_profile.html", user=user)

@app.route("/posts/<int:post_id>/like", methods=["POST"])
@protected
def like_post(post_id):
    try:
        user_id = session['user']['id']
        post = Post.query.get(post_id)
        if not post:
            return redirect(url_for("error", message="Post not found."))

        existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
        existing_dislike = Dislike.query.filter_by(user_id=user_id, post_id=post_id).first()
        
        if existing_dislike:
            db.session.delete(existing_dislike)

        if existing_like:
            db.session.delete(existing_like)
        else:
            like = Like(user_id=user_id, post_id=post_id)
            db.session.add(like)
            notification = Notification(user_id=post.user_id, post_id=post_id, action="like")
            db.session.add(notification)
        
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))


@app.route("/posts/<int:post_id>/dislike", methods=["POST"])
@protected
def dislike_post(post_id):
    try:
        user_id = session['user']['id']
        post = Post.query.get(post_id)
        if not post:
            return redirect(url_for("error", message="Post not found."))

        existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
        existing_dislike = Dislike.query.filter_by(user_id=user_id, post_id=post_id).first()
        
        if existing_like:
            db.session.delete(existing_like)

        if existing_dislike:
            db.session.delete(existing_dislike)
        else:
            dislike = Dislike(user_id=user_id, post_id=post_id)
            db.session.add(dislike)
            notification = Notification(user_id=post.user_id, post_id=post_id, action="dislike")
            db.session.add(notification)
        
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contactus')
def contactus():
    return render_template('contact_us.html')

@app.route("/upload_pfp", methods=["GET", "POST"])
@protected
def upload_pfp():
    if request.method == "POST":
        if 'profile_picture' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['profile_picture']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Update user's profile picture in the database
            user_id = session['user']['id']
            user = User.query.get(user_id)
            user.profile_picture = filename  # Store only the filename
            db.session.commit()

            return redirect(url_for('profile'))
        else:
            flash('Invalid file type. Allowed file types are: png, jpg, jpeg, gif', 'error')
            return redirect(request.url)

    # If no file is uploaded, ensure the default profile picture is set
    user_id = session['user']['id']
    user = User.query.get(user_id)
    if not user.profile_picture:
        user.profile_picture = 'static/pfp.png'  # Set default profile picture
        db.session.commit()

    return redirect(url_for("profile"))


@app.route("/posts/<int:post_id>/comment", methods=["POST"])
@protected
def comment_post(post_id):
    try:
        user_id = session['user']['id']
        content = request.form['content']
        post = Post.query.get(post_id)  # Retrieve the post object
        if not post:
            return redirect(url_for("error", message="Post not found."))

        comment = Comment(content=content, user_id=user_id, post_id=post_id)
        db.session.add(comment)
        
        notification = Notification(user_id=post.user_id, post_id=post_id, action="comment", comment_content=content)
        db.session.add(notification)
        
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))


    
@app.route("/posts/<int:post_id>/comments/<int:comment_id>/edit", methods=["GET", "POST"])
@protected
def edit_comment(post_id, comment_id):
    try:
        comment = Comment.query.get(comment_id)
        if not comment:
            return redirect(url_for("error", message="Comment not found."))

        if session['user']['id'] != comment.user_id:
            return redirect(url_for("error", message="You are not authorized to edit this comment."))

        if request.method == "POST":
            content = request.form['content']
            comment.content = content
            db.session.commit()
            return redirect(url_for("posts"))

        return render_template("edit_comment.html", comment=comment)
    except Exception as e:
        return render_template("error.html", message=str(e))


@app.route("/delete_profile", methods=["POST"])
@protected
def delete_profile():
    try:
        user_id = session['user']['id']
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for("error", message="User not found."))

        # Delete user's comments
        Comment.query.filter_by(user_id=user_id).delete()
        Post.query.filter_by(user_id=user_id).delete()
        Dislike.query.filter_by(user_id=user_id).delete()
        Like.query.filter_by(user_id=user_id).delete()
        Message.query.filter_by(user_id=user_id).delete()
        Favorite.query.filter_by(user_id=user_id).delete()
        # Delete user's posts
        posts = Post.query.filter_by(user_id=user_id).all()
        for post in posts:
            # Delete comments associated with the post
            Comment.query.filter_by(post_id=post.id).delete()
            # Delete the post itself
            db.session.delete(post)

        # Delete user
        db.session.delete(user)
        db.session.commit()

        # Logout user
        session.pop("user", None)

        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/posts/<int:post_id>/comments/<int:comment_id>/delete", methods=["POST"])
@protected
def delete_comment(post_id, comment_id):
    try:
        comment = Comment.query.get(comment_id)
        if not comment:
            return redirect(url_for("error", message="Comment not found."))

        if session['user']['id'] != comment.user_id:
            return redirect(url_for("error", message="You are not authorized to delete this comment."))

        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/posts/<int:post_id>/comments/<int:comment_id>/reply", methods=["POST"])
@protected
def reply_to_comment(post_id, comment_id):
    try:
        user_id = session['user']['id']
        content = request.form['content']
        
        # Check if the comment exists
        comment = Comment.query.get(comment_id)
        if not comment:
            return redirect(url_for("error", message="Comment not found."))
        
        # Create a new comment as a reply to the existing comment
        reply = Comment(content=content, user_id=user_id, post_id=post_id)
        reply.reply_to = comment_id  # Store the parent comment ID for reference
        
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/user/<int:user_id>")
def view_profile(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return render_template("error.html", message="User not found.")
        
        user_posts = Post.query.filter_by(user_id=user_id).all()
        
        return render_template("profile.html", user=user, user_posts=user_posts)
    except Exception as e:
        return render_template("error.html", message=str(e))
    
@app.route("/chat", methods=["GET", "POST"])
@protected
def chat():
    if request.method == "POST":
        try:
            content = request.form["content"]
            user_id = session['user']['id']
            message = Message(content=content, user_id=user_id)
            db.session.add(message)
            db.session.commit()
            return redirect(url_for("chat"))
        except Exception as e:
            return render_template("error.html", message=str(e))
    else:
        messages = Message.query.all()
        return render_template("chat.html", messages=messages)

@app.route("/delete_message/<int:message_id>", methods=["POST"])
@protected
def delete_message(message_id):
    try:
        message = Message.query.get_or_404(message_id)
        user_id = session['user']['id']
        if message.user_id == user_id or session['user']['is_admin']:
            db.session.delete(message)
            db.session.commit()
            return redirect(url_for("chat"))
        else:
            return render_template("error.html", message="You are not authorized to delete this message.")
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/liked_posts")
@protected
def liked_posts():
    try:
        user_id = session['user']['id']
        liked_posts = Post.query.join(Like, (Like.post_id == Post.id)).filter(Like.user_id == user_id).all()
        return render_template("liked_posts.html", liked_posts=liked_posts)
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/disliked_posts")
@protected
def disliked_posts():
    try:
        user_id = session['user']['id']
        disliked_posts = Post.query.join(Dislike, (Dislike.post_id == Post.id)).filter(Dislike.user_id == user_id).all()
        return render_template("disliked_posts.html", disliked_posts=disliked_posts)
    except Exception as e:
        return render_template("error.html", message=str(e))


@app.route("/posts/<int:post_id>/favorite", methods=["POST"])
@protected
def favorite_post(post_id):
    try:
        user_id = session['user']['id']
        post = Post.query.get(post_id)
        if not post:
            return redirect(url_for("error", message="Post not found."))

        existing_favorite = Favorite.query.filter_by(user_id=user_id, post_id=post_id).first()

        if existing_favorite:
            db.session.delete(existing_favorite)
        else:
            favorite = Favorite(user_id=user_id, post_id=post_id)
            db.session.add(favorite)
        
        db.session.commit()
        return redirect(url_for("posts"))
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/favorites")
@protected
def view_favorites():
    try:
        user_id = session['user']['id']
        favorite_posts = Post.query.join(Favorite, (Favorite.post_id == Post.id)).filter(Favorite.user_id == user_id).all()
        return render_template("favorites.html", favorite_posts=favorite_posts)
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/search", methods=["POST"])
def search():
    if request.method == "POST":
        search_query = request.form.get("search_query")
        if search_query:
            user = User.query.filter_by(username=search_query).first()
            if user:
                return redirect(url_for("view_profile", user_id=user.id))
            else:
                flash(f"No user found with the username '{search_query}'.", "warning")
                return redirect(url_for("posts"))
        else:
            flash("Please enter a username to search for.", "warning")
            return redirect(url_for("posts"))

@app.route("/commented_posts")
@protected
def commented_posts():
    try:
        user_id = session['user']['id']
        commented_posts = Post.query.join(Comment, (Comment.post_id == Post.id)).filter(Comment.user_id == user_id).all()
        return render_template("commented_posts.html", commented_posts=commented_posts)
    except Exception as e:
        return render_template("error.html", message=str(e))
    
@app.route("/notifications")
@protected
def view_notifications():
    try:
        user_id = session['user']['id']
        notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()
        return render_template("notifications.html", notifications=notifications)
    except Exception as e:
        return render_template("error.html", message=str(e))

@app.route("/notifications/read/<int:notification_id>", methods=["POST"])
@protected
def mark_notification_as_read(notification_id):
    try:
        notification = Notification.query.get(notification_id)
        if not notification or notification.user_id != session['user']['id']:
            return redirect(url_for("error", message="Notification not found or not authorized."))

        notification.is_read = True
        db.session.commit()
        return redirect(url_for("view_notifications"))
    except Exception as e:
        return render_template("error.html", message=str(e))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)