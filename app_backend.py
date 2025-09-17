import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt


from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)  
bcrypt = Bcrypt(app)


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"] 
)
limiter.init_app(app)


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      
    SESSION_COOKIE_SECURE=True,       
    SESSION_COOKIE_SAMESITE='Lax',    
    PERMANENT_SESSION_LIFETIME=1800    
)


class RegisterForm(FlaskForm):
    username = StringField('İstifadəçi adı', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Şifrə', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Şifrə təkrarı', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Qeydiyyat')

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Şifrə', validators=[DataRequired()])
    submit = SubmitField('Giriş')


DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )''')
        db.commit()

init_db()


@app.route('/')
def index():
    return redirect(url_for('login'))  


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        try:
            db = get_db()
            c = db.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                      (username, email, password))
            db.commit()
            flash("Qeydiyyat uğurla tamamlandı!", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Bu e-mail artıq istifadə olunur!", "danger")

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        db = get_db()
        c = db.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash("E-mail və ya şifrə yanlışdır!", "danger")

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Əvvəlcə daxil olun!", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
def logout():
    session.clear()
    flash("Çıxış edildi!", "info")
    return redirect(url_for('login'))


@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Çox tez-tez cəhd etdiniz! Bir az gözləyin.", "warning")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

