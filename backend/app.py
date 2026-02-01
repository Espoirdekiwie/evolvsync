"""
EvolvSync Backend API - Complete Single File Version
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import json
from collections import Counter

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evolvsync.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-in-production-67890'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Initialize extensions
CORS(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    
    entries = db.relationship('Entry', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }

class Entry(db.Model):
    __tablename__ = 'entries'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    entry_type = db.Column(db.String(20), default='text')
    sentiment = db.Column(db.String(20))
    word_count = db.Column(db.Integer)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'text': self.text,
            'category': self.category,
            'entry_type': self.entry_type,
            'sentiment': self.sentiment,
            'word_count': self.word_count
        }

# ==================== ANALYTICS FUNCTIONS ====================

def analyze_sentiment(text):
    positive_words = ['happy', 'great', 'excellent', 'amazing', 'wonderful', 'good', 'better',
                     'progress', 'achieved', 'success', 'proud', 'grateful', 'love', 'joy']
    negative_words = ['sad', 'bad', 'terrible', 'stressed', 'anxious', 'worried',
                     'failed', 'difficult', 'struggle', 'pain', 'angry']
    
    text_lower = text.lower()
    positive_count = sum(1 for word in positive_words if word in text_lower)
    negative_count = sum(1 for word in negative_words if word in text_lower)
    
    if positive_count > negative_count:
        return 'Positive'
    elif negative_count > positive_count:
        return 'Challenging'
    return 'Neutral'

def calculate_streak(entries):
    if not entries:
        return 0
    
    dates = sorted(set(entry.timestamp.date() for entry in entries))
    if not dates:
        return 0
    
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    
    if dates[-1] not in [today, yesterday]:
        return 0
    
    streak = 1
    for i in range(len(dates) - 2, -1, -1):
        expected_date = dates[i + 1] - timedelta(days=1)
        if dates[i] == expected_date:
            streak += 1
        else:
            break
    
    return streak

def calculate_consistency(entries):
    if not entries:
        return 0.0
    
    first_date = min(entry.timestamp.date() for entry in entries)
    last_date = max(entry.timestamp.date() for entry in entries)
    total_days = (last_date - first_date).days + 1
    unique_days = len(set(entry.timestamp.date() for entry in entries))
    
    return round((unique_days / total_days) * 100, 1)

# ==================== ROUTES ====================

@app.route('/')
def index():
    return jsonify({
        'message': 'EvolvSync API v0.25',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'register': '/api/auth/register',
            'login': '/api/auth/login',
            'entries': '/api/entries',
            'dashboard': '/api/analytics/dashboard'
        }
    }), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '0.25'
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password required'}), 400
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            username=data['username'],
            email=data.get('email'),
            password_hash=hashed_password
        )
        
        db.session.add(user)
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        
        if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/entries', methods=['GET'])
@jwt_required()
def get_entries():
    try:
        user_id = get_jwt_identity()
        entries = Entry.query.filter_by(user_id=user_id).order_by(Entry.timestamp.desc()).all()
        
        return jsonify({
            'entries': [entry.to_dict() for entry in entries],
            'total': len(entries)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/entries', methods=['POST'])
@jwt_required()
def create_entry():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('text') or not data.get('category'):
            return jsonify({'error': 'Text and category required'}), 400
        
        sentiment = analyze_sentiment(data['text'])
        
        entry = Entry(
            user_id=user_id,
            text=data['text'],
            category=data['category'],
            sentiment=sentiment,
            entry_type=data.get('entry_type', 'text'),
            word_count=len(data['text'].split())
        )
        
        db.session.add(entry)
        db.session.commit()
        
        return jsonify({
            'message': 'Entry created successfully',
            'entry': entry.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user_id = get_jwt_identity()
        entries = Entry.query.filter_by(user_id=user_id).all()
        
        if not entries:
            return jsonify({
                'total_entries': 0,
                'voice_entries': 0,
                'current_streak': 0,
                'total_words': 0
            }), 200
        
        voice_entries = len([e for e in entries if e.entry_type == 'voice'])
        total_words = sum(e.word_count or 0 for e in entries)
        
        return jsonify({
            'total_entries': len(entries),
            'voice_entries': voice_entries,
            'current_streak': calculate_streak(entries),
            'total_words': total_words,
            'consistency': calculate_consistency(entries)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("\n" + "="*50)
        print("✅ Database tables created successfully!")
        print("✅ EvolvSync Backend Server Starting...")
        print("="*50)
        print("\n🌐 Server running at: http://localhost:5000")
        print("📊 Health check: http://localhost:5000/api/health")
        print("📚 API info: http://localhost:5000/")
        print("\n⚡ Press CTRL+C to quit\n")
        print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
