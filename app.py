"""
DelegateHub Backend — Flask + JWT + Google OAuth + SQLite
Run: python app.py
"""
import os
from dotenv import load_dotenv
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)

print("KEY LOADED:", os.getenv("ANTHROPIC_API_KEY"))
print("KEY LOADED:", os.getenv("ANTHROPIC_API_KEY"))
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import uuid


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ── CONFIG ────────────────────────────────────────────────────────
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///delegatehub.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'delegatehub-super-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ── MODELS ────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email        = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name         = db.Column(db.String(255), nullable=False)
    password_hash= db.Column(db.String(255), nullable=True)  # null for Google OAuth users
    google_id    = db.Column(db.String(255), unique=True, nullable=True)
    avatar_url   = db.Column(db.String(512), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_login   = db.Column(db.DateTime, default=datetime.utcnow)
    is_active    = db.Column(db.Boolean, default=True)
    # Relations
    resolutions  = db.relationship('Resolution', backref='author', lazy=True, cascade='all, delete-orphan')
    country_notes= db.relationship('CountryNote', backref='author', lazy=True, cascade='all, delete-orphan')
    bookmarks    = db.relationship('Bookmark', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'avatar_url': self.avatar_url,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat(),
        }


class Resolution(db.Model):
    __tablename__ = 'resolutions'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    title        = db.Column(db.String(500), nullable=False)
    committee    = db.Column(db.String(255), nullable=False)
    topic        = db.Column(db.String(1000), nullable=False)
    sponsors     = db.Column(db.String(1000), nullable=True)
    signatories  = db.Column(db.String(1000), nullable=True)
    preamb_clauses = db.Column(db.Text, nullable=True)   # JSON string
    oper_clauses   = db.Column(db.Text, nullable=True)   # JSON string
    ai_feedback  = db.Column(db.Text, nullable=True)
    status       = db.Column(db.String(50), default='draft')  # draft | submitted | passed | failed
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_public    = db.Column(db.Boolean, default=False)

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'title': self.title,
            'committee': self.committee,
            'topic': self.topic,
            'sponsors': self.sponsors,
            'signatories': self.signatories,
            'preamb_clauses': json.loads(self.preamb_clauses) if self.preamb_clauses else [],
            'oper_clauses': json.loads(self.oper_clauses) if self.oper_clauses else [],
            'ai_feedback': self.ai_feedback,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_public': self.is_public,
        }


class CountryNote(db.Model):
    __tablename__ = 'country_notes'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    country_name = db.Column(db.String(255), nullable=False)
    notes        = db.Column(db.Text, nullable=True)
    assigned_bloc= db.Column(db.String(255), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'country_code': self.country_code,
            'country_name': self.country_name,
            'notes': self.notes,
            'assigned_bloc': self.assigned_bloc,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class Bookmark(db.Model):
    __tablename__ = 'bookmarks'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    type         = db.Column(db.String(50), nullable=False)   # country | rule | guide
    ref_id       = db.Column(db.String(255), nullable=False)
    ref_name     = db.Column(db.String(500), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'ref_id': self.ref_id,
            'ref_name': self.ref_name,
            'created_at': self.created_at.isoformat(),
        }


# ── HELPERS ───────────────────────────────────────────────────────
def validate_email(email):
    import re
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email)

def success(data=None, message='Success', status=200):
    resp = {'success': True, 'message': message}
    if data is not None:
        resp['data'] = data
    return jsonify(resp), status

def error(message='Error', status=400, errors=None):
    resp = {'success': False, 'message': message}
    if errors:
        resp['errors'] = errors
    return jsonify(resp), status


# ── AUTH ROUTES ───────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    name     = (data.get('name') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    # Validation
    errs = {}
    if not name or len(name) < 2:
        errs['name'] = 'Name must be at least 2 characters'
    if not email or not validate_email(email):
        errs['email'] = 'Invalid email address'
    if not password or len(password) < 8:
        errs['password'] = 'Password must be at least 8 characters'
    if errs:
        return error('Validation failed', 422, errs)

    if User.query.filter_by(email=email).first():
        return error('An account with this email already exists', 409)

    user = User(email=email, name=name)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    access_token  = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return success({
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token,
    }, 'Account created successfully', 201)


@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return error('Email and password are required')

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return error('Invalid email or password', 401)

    if not user.is_active:
        return error('This account has been deactivated', 403)

    user.last_login = datetime.utcnow()
    db.session.commit()

    access_token  = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return success({
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token,
    }, 'Logged in successfully')


@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data     = request.get_json()
    token    = data.get('token') or data.get('credential') or ''

    if not token:
        return error('Google token is required')

    try:
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        google_id = idinfo['sub']
        email     = idinfo['email'].lower()
        name      = idinfo.get('name', email.split('@')[0])
        avatar    = idinfo.get('picture', '')
    except Exception as e:
        return error(f'Google token verification failed: {str(e)}', 401)

    # Find or create user
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user:
            user.google_id  = google_id
            user.avatar_url = avatar
        else:
            user = User(email=email, name=name, google_id=google_id, avatar_url=avatar)
            db.session.add(user)

    user.last_login = datetime.utcnow()
    db.session.commit()

    access_token  = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return success({
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token,
    }, 'Logged in with Google')


@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return success({'access_token': access_token})


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)
    if not user:
        return error('User not found', 404)
    return success({'user': user.to_dict()})


@app.route('/api/auth/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)
    data    = request.get_json()

    if 'name' in data and len(data['name'].strip()) >= 2:
        user.name = data['name'].strip()
    if 'avatar_url' in data:
        user.avatar_url = data['avatar_url']

    db.session.commit()
    return success({'user': user.to_dict()}, 'Profile updated')


@app.route('/api/auth/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    user_id  = get_jwt_identity()
    user     = User.query.get(user_id)
    data     = request.get_json()
    old_pw   = data.get('old_password', '')
    new_pw   = data.get('new_password', '')

    if not user.check_password(old_pw):
        return error('Current password is incorrect', 401)
    if len(new_pw) < 8:
        return error('New password must be at least 8 characters')

    user.set_password(new_pw)
    db.session.commit()
    return success(message='Password changed successfully')


# ── RESOLUTIONS ───────────────────────────────────────────────────
@app.route('/api/resolutions', methods=['GET'])
@jwt_required()
def get_resolutions():
    user_id = get_jwt_identity()
    page    = request.args.get('page', 1, type=int)
    per_page= request.args.get('per_page', 20, type=int)
    status  = request.args.get('status', None)

    q = Resolution.query.filter_by(user_id=user_id)
    if status:
        q = q.filter_by(status=status)
    q = q.order_by(Resolution.updated_at.desc())
    paginated = q.paginate(page=page, per_page=per_page, error_out=False)

    return success({
        'resolutions': [r.to_dict() for r in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page,
    })


@app.route('/api/resolutions', methods=['POST'])
@jwt_required()
def create_resolution():
    import json
    user_id = get_jwt_identity()
    data    = request.get_json()

    title   = (data.get('title') or data.get('topic') or 'Untitled Resolution').strip()
    if not title:
        return error('Resolution title is required')

    res = Resolution(
        user_id        = user_id,
        title          = title,
        committee      = data.get('committee', 'General Assembly'),
        topic          = data.get('topic', ''),
        sponsors       = data.get('sponsors', ''),
        signatories    = data.get('signatories', ''),
        preamb_clauses = json.dumps(data.get('preamb_clauses', [])),
        oper_clauses   = json.dumps(data.get('oper_clauses', [])),
        ai_feedback    = data.get('ai_feedback', ''),
        status         = data.get('status', 'draft'),
        is_public      = data.get('is_public', False),
    )
    db.session.add(res)
    db.session.commit()
    return success({'resolution': res.to_dict()}, 'Resolution saved', 201)


@app.route('/api/resolutions/<res_id>', methods=['GET'])
@jwt_required()
def get_resolution(res_id):
    user_id = get_jwt_identity()
    res     = Resolution.query.filter_by(id=res_id, user_id=user_id).first()
    if not res:
        return error('Resolution not found', 404)
    return success({'resolution': res.to_dict()})


@app.route('/api/resolutions/<res_id>', methods=['PUT'])
@jwt_required()
def update_resolution(res_id):
    import json
    user_id = get_jwt_identity()
    res     = Resolution.query.filter_by(id=res_id, user_id=user_id).first()
    if not res:
        return error('Resolution not found', 404)

    data = request.get_json()
    for field in ['title','committee','topic','sponsors','signatories','ai_feedback','status']:
        if field in data:
            setattr(res, field, data[field])
    if 'preamb_clauses' in data:
        res.preamb_clauses = json.dumps(data['preamb_clauses'])
    if 'oper_clauses' in data:
        res.oper_clauses = json.dumps(data['oper_clauses'])
    if 'is_public' in data:
        res.is_public = data['is_public']

    res.updated_at = datetime.utcnow()
    db.session.commit()
    return success({'resolution': res.to_dict()}, 'Resolution updated')


@app.route('/api/resolutions/<res_id>', methods=['DELETE'])
@jwt_required()
def delete_resolution(res_id):
    user_id = get_jwt_identity()
    res     = Resolution.query.filter_by(id=res_id, user_id=user_id).first()
    if not res:
        return error('Resolution not found', 404)
    db.session.delete(res)
    db.session.commit()
    return success(message='Resolution deleted')


# ── COUNTRY NOTES ─────────────────────────────────────────────────
@app.route('/api/country-notes', methods=['GET'])
@jwt_required()
def get_country_notes():
    user_id = get_jwt_identity()
    notes   = CountryNote.query.filter_by(user_id=user_id).order_by(CountryNote.updated_at.desc()).all()
    return success({'notes': [n.to_dict() for n in notes]})


@app.route('/api/country-notes', methods=['POST'])
@jwt_required()
def save_country_note():
    user_id = get_jwt_identity()
    data    = request.get_json()
    code    = data.get('country_code', '').upper()
    if not code:
        return error('Country code is required')

    note = CountryNote.query.filter_by(user_id=user_id, country_code=code).first()
    if note:
        note.notes        = data.get('notes', note.notes)
        note.assigned_bloc= data.get('assigned_bloc', note.assigned_bloc)
        note.updated_at   = datetime.utcnow()
    else:
        note = CountryNote(
            user_id      = user_id,
            country_code = code,
            country_name = data.get('country_name', code),
            notes        = data.get('notes', ''),
            assigned_bloc= data.get('assigned_bloc', ''),
        )
        db.session.add(note)

    db.session.commit()
    return success({'note': note.to_dict()}, 'Note saved')


@app.route('/api/country-notes/<code>', methods=['DELETE'])
@jwt_required()
def delete_country_note(code):
    user_id = get_jwt_identity()
    note    = CountryNote.query.filter_by(user_id=user_id, country_code=code.upper()).first()
    if not note:
        return error('Note not found', 404)
    db.session.delete(note)
    db.session.commit()
    return success(message='Note deleted')


# ── BOOKMARKS ─────────────────────────────────────────────────────
@app.route('/api/bookmarks', methods=['GET'])
@jwt_required()
def get_bookmarks():
    user_id   = get_jwt_identity()
    bookmarks = Bookmark.query.filter_by(user_id=user_id).order_by(Bookmark.created_at.desc()).all()
    return success({'bookmarks': [b.to_dict() for b in bookmarks]})


@app.route('/api/bookmarks', methods=['POST'])
@jwt_required()
def add_bookmark():
    user_id  = get_jwt_identity()
    data     = request.get_json()
    btype    = data.get('type', '')
    ref_id   = data.get('ref_id', '')
    if not btype or not ref_id:
        return error('type and ref_id are required')

    existing = Bookmark.query.filter_by(user_id=user_id, type=btype, ref_id=ref_id).first()
    if existing:
        return success({'bookmark': existing.to_dict()}, 'Already bookmarked')

    b = Bookmark(user_id=user_id, type=btype, ref_id=ref_id, ref_name=data.get('ref_name',''))
    db.session.add(b)
    db.session.commit()
    return success({'bookmark': b.to_dict()}, 'Bookmarked', 201)


@app.route('/api/bookmarks/<bm_id>', methods=['DELETE'])
@jwt_required()
def remove_bookmark(bm_id):
    user_id = get_jwt_identity()
    b = Bookmark.query.filter_by(id=bm_id, user_id=user_id).first()
    if not b:
        return error('Bookmark not found', 404)
    db.session.delete(b)
    db.session.commit()
    return success(message='Bookmark removed')


# ── DASHBOARD STATS ───────────────────────────────────────────────
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    user_id = get_jwt_identity()
    user    = User.query.get(user_id)
    res_count      = Resolution.query.filter_by(user_id=user_id).count()
    draft_count    = Resolution.query.filter_by(user_id=user_id, status='draft').count()
    submitted_count= Resolution.query.filter_by(user_id=user_id, status='submitted').count()
    country_count  = CountryNote.query.filter_by(user_id=user_id).count()
    bookmark_count = Bookmark.query.filter_by(user_id=user_id).count()
    recent_res     = Resolution.query.filter_by(user_id=user_id).order_by(Resolution.updated_at.desc()).limit(5).all()

    return success({
        'user': user.to_dict(),
        'stats': {
            'total_resolutions': res_count,
            'drafts': draft_count,
            'submitted': submitted_count,
            'country_notes': country_count,
            'bookmarks': bookmark_count,
        },
        'recent_resolutions': [r.to_dict() for r in recent_res],
    })


# ── HEALTH CHECK ─────────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'DelegateHub API', 'version': '1.0.0'})


# ── INIT ──────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
@app.route("/api/ai/country", methods=["POST"])
def ai_country():
    from anthropic import Anthropic
    import os

    client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    data = request.get_json()
    country = data.get("country")
    region = data.get("region")
    subregion = data.get("subregion")

    prompt = f"Give MUN country profile for {country} ({region}) in JSON format."

    try:
        res = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=900,
            messages=[{"role": "user", "content": prompt}]
        )

        return jsonify({
            "text": res.content[0].text
        })

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
port = int(os.environ.get("PORT", 5001))
app.run(host="0.0.0.0", port=port)