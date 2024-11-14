from flask import Flask, flash, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from forms import RegisterForm
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime   

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = "pogi si owen"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

''' 
-----------------------------------------------
               Routes Section
-----------------------------------------------
'''

@app.route("/register", methods=['GET', 'POST'])
def register():
    username = None
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user = User.query.filter_by(username=register_form.username.data).first()
        if user is None:
            hashed_pw = generate_password_hash(register_form.password.data, "sha256")
            user = User(username=register_form.username.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        username = register_form.username.data
        register_form.username.data = ''
        register_form.password.data = ''

        flash("Account created successfully")
    our_users = User.query.order_by(User.date_added)
    return render_template('register.html', 
                           register_form=register_form,
                           username=username, 
                           our_users=our_users)

''' 
-----------------------------------------------
               Models Section
-----------------------------------------------
'''

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(120), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @property 
    def password(self):
        raise AttributeError("Password is not a readable attribute")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}')"
    
class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    goal_name = db.Column(db.String(100), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    saved_amount = db.Column(db.Float, nullable=False, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Links to the User model
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Goal('{self.goal_name}', Target: {self.target_amount}, Saved: {self.saved_amount})"