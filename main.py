from flask import Flask, render_template, url_for, flash, redirect, session, jsonify, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo
import os
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your_secret_key'
DATABASE = 'site.db'
PATH=f"instance/{DATABASE}"
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DATABASE}"
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(250), unique=True, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    bookings = db.relationship('Bookings', back_populates='event')


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bookings = db.relationship('Bookings', back_populates='user')



class Bookings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    num_seats = db.Column(db.Integer, nullable=False)

    user = db.relationship('Users', back_populates='bookings')
    event = db.relationship('Events', back_populates='bookings')

# Database functions
def init_db():
    with app.app_context():
        db.create_all()

#Book tickets
def book(ticket,num_seats):
    if ticket and ticket.available_seats >= num_seats:
        ticket.available_seats -= num_seats
        new_booking = Bookings(user_id=session['user_id'], event_id=ticket.id, num_seats=num_seats)
        db.session.add(new_booking)
        db.session.commit()
        flash("Ticket booked successfully!", "success")
        return True
    else:
        flash("Not enough seats available.", "danger")

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=5, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BookTicketForm(FlaskForm):
    event_name = StringField('Event Name', validators=[DataRequired()])
    num_seats = IntegerField('Number of Seats', validators=[DataRequired()])
    submit = SubmitField('Book')

# Routes
@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        with app.app_context():
            new_user = Users(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()

        flash("Account created!", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Login Unsuccessful. Check username and password", "danger")
    return render_template("login.html", form=form)

@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    if 'user_id' not in session:
        flash("Please log in to view tickets.", "danger")
        return redirect(url_for("login"))

    tickets = Events.query.all()
    return render_template("tickets.html", tickets=tickets)

@app.route("/book_ticket", methods=["GET", "POST"])
def book_ticket():
    if 'user_id' not in session:
        flash("Please log in to book a ticket.", "danger")
        return redirect(url_for("login"))

    form = BookTicketForm()
    if form.validate_on_submit():
        event_name = form.event_name.data
        num_seats = form.num_seats.data

        ticket = Events.query.filter_by(event_name=event_name).first()

        booked=book(ticket,num_seats)
        print(booked)
        if booked:
            return redirect(url_for("tickets"))
    return render_template("book_ticket.html", form=form)


# API Routes

# Authentication Endpoint
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = Users.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        # Create JWT Token
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200

    return jsonify({"message": "Invalid username or password"}), 401

# Protected Endpoint to Get User Bookings
@app.route('/api/user/bookings', methods=['GET'])
@jwt_required()  # Require JWT for access
def get_user_bookings():
    user_id = get_jwt_identity()  # Get user ID from the JWT
    user = Users.query.get(user_id)

    if user:
        bookings = user.bookings
        bookings_list = []
        for booking in bookings:
            booking_data = {
                'event_name': booking.event.event_name,
                'seats_booked': booking.num_seats
            }
            bookings_list.append(booking_data)

        return jsonify({'username': user.username, 'bookings': bookings_list}), 200

    return jsonify({"message": "User not found"}), 404


@app.route("/api/tickets/book", methods =["POST"])
@jwt_required()  # Require JWT for access
def book_api():
    event_name = requests.args.get("event_name")
    seats = requests.args.get("seats")
    book(ticket=event_name, num_seats=seats)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

# Initialize database with schema
if __name__ == "__main__":
    if not os.path.exists(PATH):
        init_db()
    app.run(debug=True)
