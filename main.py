from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.secret_key = 'secret-key-goes-here' # Any string just keep it secret

login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    def __init__(self, email: str, password: str, name: str):
        self.email = email
        self.password = password
        self.name = name

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash(message="Duplicate detected! This email’s already in use.", category="info")
            return redirect(url_for('login'))

        hash_and_salted_pass = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )

        new_user = User(
            email=request.form.get("email"),
            password=hash_and_salted_pass,
            name=request.form.get("name"),
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash(f'Access granted, Agent {current_user.name} 🔐', "success")
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user or not check_password_hash(user.password, password):
            flash('Authentication failed. The system detected invalid credentials. 🛑', "danger")
            return redirect(url_for('login'))
        else:
            login_user(user)
            flash(f'Access granted, Agent {current_user.name} 🔐', "success")
            return redirect(url_for("secrets"))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    flash(f"Agent {current_user.name}, you've safely exited the system. 🛡️", "success")
    logout_user()
    return redirect(url_for("home"))


@app.route('/download', methods=["POST"])
@login_required
def download():
    return send_from_directory(
        'static', path="files/cheat_sheet.pdf", # as_attachment=True
    )

if __name__ == "__main__":
    app.run(debug=True)
