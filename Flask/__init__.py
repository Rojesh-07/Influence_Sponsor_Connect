from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from Flask.models import User
    return User.query.get(int(user_id))

# Ensure models are imported before db.create_all() is called
import Flask.models

with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("Database tables created.")

    from Flask.models import User
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        print("Creating admin user...")
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin'),
            role='admin',
            company_name=None,
            category=None,
            niche=None
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")

from Flask import routes
