from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from flask_wtf.csrf import CSRFProtect
import email_validator
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv("./.env")
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['WTF_SECRET_KEY'] = os.getenv("WTF_SECRET_KEY")
csrf = CSRFProtect(app)
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = "/login"

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    author = db.relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = db.relationship("BlogPost", back_populates="comments")
    content = db.Column(db.Text, nullable=False)


class User(db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    is_act = db.Column(db.Boolean, nullable=False)
    is_anon = db.Column(db.Boolean, nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")


    def is_active(self):
        return self.is_act

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return self.is_anon

    def get_id(self):
        return self.user_id


db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Decorator for functionalities requiring admin privileges
def admin_required(f):
    @wraps(f)
    def check_admin():
        print("checking if user is admin")
        if current_user and current_user.__getattr__("user_id") == 1:
            print(f"User ID {current_user.user_id}")
            return f()
        return redirect(url_for("get_all_posts"))
    return check_admin


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    msg = ""
    if form.validate_on_submit():
        check_existing = User.query.filter_by(email=form.email.data).first()
        if not check_existing:
            db.session.add(User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=32),
                is_act=True,
                is_anon=False
            ))
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            msg = 'User or email exist already, try something else'
    return render_template("register.html", form=form, msg=msg, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    msg = ""
    if form.validate_on_submit():
        check_user = User.query.filter_by(email=form.email.data).first()
        if check_user and check_password_hash(password=form.password.data,
                                              pwhash=check_user.password):
            login_user(check_user)
            return (redirect(url_for("get_all_posts")))
        else:
            msg = "Login Error!!"
    return render_template("login.html", form=form, msg=msg, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        db.session.add(Comment(
            content=form.comment.data,
            author_id=current_user.user_id,
            post_id=post_id
        ))
        db.session.commit()
    post_comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post,
                           post_comments=post_comments,
                           form=form, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@login_required
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.user_id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)



@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
