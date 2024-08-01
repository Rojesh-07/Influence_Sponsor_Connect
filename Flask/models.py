from Flask import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'sponsor' or 'influencer' or 'admin'
    company_name = db.Column(db.String(100))  # Only for sponsors
    name = db.Column(db.String(100))  # Only for infl
    category = db.Column(db.String(50))  # For influencers: category
    niche = db.Column(db.String(50))  # For influencers: niche
    reach = db.Column(db.Integer)  # For influencers: reach
    budget = db.Column(db.Float)
    platforms = db.Column(db.String(120))  # Store platforms as comma-separated string
    blacklist = db.Column(db.Boolean(),default=False)

class Campaign(db.Model,UserMixin):
    __tablename__ = 'campaigns'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Added user_id
    campaign_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(80))
    budget = db.Column(db.Float)
    status = db.Column(db.String(80))
    products = db.Column(db.String(200))
    goals = db.Column(db.String(200))
    progress = db.Column(db.Integer)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    ad_requests = db.relationship('AdRequest', back_populates='campaign', cascade="all, delete-orphan")
    
    # Relationship with User
    sponsor = db.relationship('User', backref=db.backref('campaigns', lazy=True))


class AdRequest(db.Model,UserMixin):
    __tablename__ = 'ad_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    ad_name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    goal = db.Column(db.String(120), nullable=False)
    influencer_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(120), nullable=False)
    
    # Relationship with Campaign
    campaign = db.relationship('Campaign', back_populates='ad_requests')

    # Added user_id for the sponsor who created the campaign
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship with User
    sponsor = db.relationship('User', backref=db.backref('ad_requests', lazy=True))


class FlaggedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    flagged_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('flagged', lazy=True))