"""Server-validated authentication and private-key unlock forms."""

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(min=2, max=200)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128)])
    confirm_password = PasswordField(
        "Confirm password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Log in")


class PasswordUnlockForm(FlaskForm):
    password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Continue")
