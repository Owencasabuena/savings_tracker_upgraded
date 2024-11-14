from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), EqualTo('confirmed_pasword', message="Password Must Match")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])    
    submit = SubmitField('Register')