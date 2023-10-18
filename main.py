from datetime import datetime, date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ResetRequestForm, ResetPasswordForm
import bleach
from secrets import token_hex
from itsdangerous import URLSafeTimedSerializer as Serializer
from itsdangerous.exc import BadTimeSignature
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
from flask_debugtoolbar import DebugToolbarExtension

# ----------------------------------------- APP CONFIGURATIONS ----------------------------------------- #

app = Flask(__name__)
app.config['SECRET_KEY'] = token_hex(32)
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager(app)

# DebugToolbar Configuration
# app.config["DEBUG_TB_TEMPLATE_EDITOR_ENABLED"] = True
# app.debug = True
# toolbar = DebugToolbarExtension(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(f):
    # We must use this @wraps() decorator here as it preserves the metadata of the original function
    @wraps(f)
    def wrapper(*args, **kwargs):
        # If current_user in authenticated and its id is "1" then we allow to execute the decorated functions, otherwise
        # we return abort with a 403 error
        if current_user.is_authenticated and current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


# Flask-Gravatar Configuration
# Gravatar is an online service which allows to create a unified online "profile". Each Gravatar profile is connected to
# an email address. When you use this email around the web, your entire profile comes with you. It's free and works for
# both registered an unregistered emails. In the case of our flask app we will be integrating Gravatar via the
# flask_gravatar module, which will allow us to dynamically create avatar images for commenter users only by using their
# email addresses. Bellow we create a Gravatar() instance and configure the basics. The actual commenter avatar images
# are rendered in the comments section inside the 'post.html' template.
gravatar = Gravatar(app,                    # must pass app
                    size=100,               # the avatar image size
                    rating='g',             # allowed rating of the user's avatar image. 'g' is generic and safe
                    default='retro',        # avatar style, there are some default values, or we can pass an image url
                    force_default=False,    # always load default image
                    force_lower=False,      # build only default avatars
                    use_ssl=False,          # if you use ssl
                    base_url=None)          # don't know


# Mail Configuration
load_dotenv()
app.config['MAIL_SERVER'] = os.getenv("SMTP_SERVER")
app.config['MAIL_PORT'] = os.getenv("SMTP_PORT")
app.config['MAIL_USERNAME'] = os.getenv("SMTP_EMAIL")
app.config['MAIL_PASSWORD'] = os.getenv("SMTP_APP_PASSWORD")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


# ----------------------------------------- FUNCTIONS ----------------------------------------- #

# Strips invalid tags/attributes from comments
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt', 'em', 'h1', 'h2', 'h3', 'h4', 'h5',
                    'h6', 'hr', 'i', 'img', 'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike', 'span', 'sub', 'sup',
                    'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'tt', 'u', 'ul']
    allowed_attrs = {'a': ['href', 'target', 'title'],
                     'img': ['src', 'alt', 'width', 'height']}
    cleaned = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    return cleaned


# Send Reset Password Email
def send_reset_email(user):
    token = User.get_reset_token(user)
    msg = Message("Password Reset",
                  sender=os.getenv("SMTP_EMAIL"),
                  recipients=[user.email])
    msg.recipients = [user.email]
    # We use the _external=True to send the user the absolute url instead of the relative url as it is used normally
    # with url_for()
    msg.body = f'''To reset your password, visit the following link:\n
{url_for("reset_token", token=token, _external=True)}\n
If you did not made this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


# Send Blog Contact Email
def send_contact_email(data):
    msg = Message("Blog Contact Message",
                  sender=os.getenv("SMTP_EMAIL"),
                  recipients=[os.getenv("ADMIN_EMAIL")])
    msg.recipients = [os.getenv("ADMIN_EMAIL")]
    msg.body = f'''New message from:\n
Name: {data["name"]}
Email: {data["email"]}
Phone: {data["phone"]}
Message: {data["message"]}
'''
    mail.send(msg)


# ----------------------------------------- DB & TABLES ----------------------------------------- #

# CONNECT TO DB
# DB_URI should be set as the database URI in the environment variables file. As an alternative default value we use the
# development sqlite URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI', 'sqlite:///posts.db')
db = SQLAlchemy(app)

salt = ""


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    # This __tablename__ attribute specifies the actual name of the table IN THE DATABASE!
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    # We create a new attribute for this model class called 'posts', which is defined as a db.relationship() with the
    # BlogPost model class. For this particular sqlalchemy syntax we must put the name of the related model class as the
    # first argument, and then we use the 'back_populates' argument with a value of 'author'. This 'author' is the name
    # of the attribute author in the BlogPost model class. The utility of back_populates is that as the name suggests,
    # it will populate this attribute author in BlogPosts with an actual User.
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")

    def get_reset_token(self):
        """This function generates a token to be used when a user requests to reset his password. The function first
        generates a salt, then uses the salt and the app 'SECRET_KEY' to generate a URLSafeTimedSerializer, which in
        term is used to encrypt the user's id."""
        global salt
        salt = token_hex(32)
        s = Serializer(app.config['SECRET_KEY'], salt=salt)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        """This function receives a token, checks if it is still valid based on the time has passed since the token
        generation and if it is, then it uses the user id received in the payload to retrieve a user from the database
        and returns it."""
        global salt
        s = Serializer(app.config['SECRET_KEY'], salt=salt)
        try:
            user_id = s.loads(token, max_age=1800)["user_id"]
        except:
            return None
        else:
            return db.get_or_404(User, user_id)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Here we must define a new attribute called 'user_id' and specify it as a db.ForeignKey(). Inside this
    # db.ForeignKey() we put the value 'users.id' because we are referencing to the NAME OF THE COLUMN 'id' OF THE TABLE
    # 'users' IN THE DATABASE!, we are NOT referencing the attribute 'id' of the MODEL class 'User'.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Here we modify the attribute 'author' to specify it as a db.relationship() with the model class 'User'. Again, we
    # use the 'back_populates' argument, and we give it a value of 'posts' to reference the posts attribute in the User
    # model class. This way it will be populated with actual Posts.
    author = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    author = db.relationship("User", back_populates="comments")
    parent_post = db.relationship("BlogPost", back_populates="comments")


class ContactMessage(db.Model):
    __tablename__ = "contact_messages"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# ----------------------------------------- FLASK ROUTE HANDLERS ----------------------------------------- #

# @app.context_processor allows to inject variables in the context of templates, as context processors run before a
# template is rendered. Here we are injecting a variable called 'year' which will be available for all templates but
# will be used in the 'footer.html' template to render the current year.
@app.context_processor
def inject_current_year():
    current_year = datetime.now().year
    return dict(year=current_year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            flash("You have already signed up. Login instead")
            return redirect(url_for("login"))
        else:
            hashed_password = generate_password_hash(password=password, method="pbkdf2:sha256", salt_length=8)
            new_user = User(email=email, password=hashed_password, name=name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            msg = Message("Welcome",
                          sender=os.getenv("SMTP_EMAIL"),
                          recipients=[email])
            msg.recipients = [email]
            msg.body = f"Welcome to Felipe's Blog! You can now comment on any post you want.\nKind regards."
            mail.send(msg)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("That email does not exist, please try again.")
        elif not check_password_hash(pwhash=user.password, password=password):
            flash("Password incorrect, please try again.")
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(text=strip_invalid_html(form.body.data),
                                  author=current_user,
                                  parent_post=requested_post)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:post_id>/<int:comment_id>")
def delete_comment(post_id, comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    if not (comment_to_delete.user_id == current_user.id or current_user.id == 1):
        abort(403)
    else:
        db.session.delete(comment_to_delete)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        contact_message = ContactMessage(name=request.form.get("name"),
                                         email=request.form.get("email"),
                                         phone=request.form.get("phone"),
                                         message=strip_invalid_html(request.form.get("message")))
        db.session.add(contact_message)
        db.session.commit()
        data = request.form.to_dict()
        send_contact_email(data)
        flash("Your message has been sent.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    form = ResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.Select(User).where(User.email == email)).scalar()
        if not user:
            flash("That email does not exist, please try again.")
        else:
            send_reset_email(user)
            flash("An email has been sent to your email address.", "success")
            return redirect(url_for("login"))
    return render_template("reset-request.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    user = User.verify_reset_token(token)
    if not user:
        flash("That is an invalid or expired token", "danger")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # if form.password == form.confirm:
        new_password = form.password.data
        new_hashed_password = generate_password_hash(password=new_password, method="pbkdf2:sha256", salt_length=8)
        user.password = new_hashed_password
        # db.session.add(user)
        db.session.commit()
        flash("Your password has been reset! You can log in now.", "success")
        return redirect(url_for("login"))
    return render_template("reset-token.html", form=form)


# ----------------------------------------- RUN APP ----------------------------------------- #

if __name__ == "__main__":
    app.run(debug=True, port=5002)
