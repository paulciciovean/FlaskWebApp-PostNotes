from flask import Blueprint, render_template, request, flash , redirect , url_for
from . import db
from .models import User
from werkzeug.security import generate_password_hash , check_password_hash
from flask_login import login_required, login_user, current_user, logout_user

auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Logged in successfully",category='succes')
                login_user(user,remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Password is incorrect",category='error')
        else: flash("User doesn't exist",category='error')
    return render_template("login.html")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
@auth.route('/Register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        phoneNumber = request.form.get("phoneNumber")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()
        if user:
            flash("This email already exists", category='error')
        elif len(email) < 6:
            flash("Email must be greater than 5 chararacters.", category='alert')
        elif len(firstName) < 3:
            flash("First Name must contain at least 2 characters. ", category='alert')
        elif phoneNumber.isdigit() == False:
            flash("Phone Number must contain only digits. ", category='alert')
        elif len(phoneNumber) < 8:
            flash("The phone number must have at least 7 numbers. ", category='alert')
        elif len(password1) < 7:
            flash("Password must be greater than 6 characters. ", category='alert')
        elif password1 != password2:
            flash("Passwords don't match.", category='alert')
        else:
            new_user = User(email = email , phone = phoneNumber ,first_name = firstName  ,password = generate_password_hash(password1,method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Account created successfully.", category='success')
            return redirect(url_for('views.home'))
    return render_template("register.html",user=current_user)

