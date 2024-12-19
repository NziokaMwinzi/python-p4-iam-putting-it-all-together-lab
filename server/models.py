from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)  # Required and unique
    _password_hash = db.Column(db.String, nullable=False)  # Secure password
    image_url = db.Column(db.String)  # Optional
    bio = db.Column(db.String)  # Optional

    recipes = db.relationship('Recipe', backref='user', cascade='all, delete-orphan')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError('Username must be present.')
        return username

    def __repr__(self):
        return f'<User {self.username}>'


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50', name='instructions_min_length'),  # Minimum 50 chars
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)  # Required
    instructions = db.Column(db.String, nullable=False)  # Required with constraint
    minutes_to_complete = db.Column(db.Integer, nullable=False)  # Required
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Required

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Title must be present.')
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError('Instructions must be at least 50 characters long.')
        return instructions

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'
