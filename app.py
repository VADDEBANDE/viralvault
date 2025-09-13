#!/usr/bin/env python3
"""
ViralVault - Enhanced Social Media Virality Betting Platform
Contains focused vulnerabilities for CTF training
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import joinedload
from functools import wraps
import secrets
import subprocess
import base64
import os
import time
import random
import threading
import uuid
from datetime import datetime, timedelta
import json
import hashlib
import requests
import urllib.parse
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'viral_vault_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///viralvault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Global cache for market status
market_status_cache = {}
cache_last_updated = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=1000.00)
    referral_code = db.Column(db.String(32), unique=True, nullable=False)
    referred_by = db.Column(db.String(32), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Market(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'), nullable=False)
    post_id = db.Column(db.String(100), nullable=False)
    target_virality = db.Column(db.Integer, nullable=False)
    initial_odds = db.Column(db.Float, nullable=False)
    virality_window_hours = db.Column(db.Integer, default=24)
    status = db.Column(db.String(20), default='active')
    final_virality = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_window_closed(self):
        return datetime.utcnow() > (self.created_at + timedelta(hours=self.virality_window_hours))

class Bet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    market_id = db.Column(db.Integer, db.ForeignKey('market.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    prediction = db.Column(db.String(20), nullable=False)  # over, under
    potential_payout = db.Column(db.Float, nullable=False)
    is_claimed = db.Column(db.Boolean, default=False)
    is_winner = db.Column(db.Boolean, nullable=True, default=None)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_viral = db.Column(db.Boolean, nullable=True)
    views = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)
    shares = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    thumbnail = db.Column(db.String(255), nullable=True)
    # Relationship to Market
    markets = db.relationship('Market', backref='video', lazy=True)
    
class SupportChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    is_user = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def generate_csrf_token():
    """Generates and stores a CSRF token in the session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def csrf_protect(f):
    """Decorator to protect routes against CSRF attacks."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method not in ["GET", "HEAD", "OPTIONS"]:
            token = session.get('_csrf_token')
            submitted = (
                request.form.get('_csrf_token') or
                request.headers.get('X-CSRF-Token') or
                (request.json.get('_csrf_token') if request.is_json and request.json else None)
            )
            if not token or token != submitted:
                print(f"CSRF token mismatch. Session token: {token}, Submitted token: {submitted}")
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated

def generate_referral_code():
    """Generate a unique referral code"""
    return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:8].upper()

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def fetch_video_stats(url):
    """Fetch real-time video statistics from supported platforms"""
    try:
        if 'tiktok.com' in url:
            video_id_match = re.search(r'video/(\d+)', url)
            if not video_id_match:
                return {
                    'views': random.randint(100000, 10000000),
                    'likes': random.randint(1000, 500000),
                    'comments': random.randint(100, 50000),
                    'shares': random.randint(50, 25000)
                }
            
            video_id = video_id_match.group(1)
            
            api_url = f'https://tiktok.livecounts.io/video/stats/{video_id}'
            
            headers = {
                'accept': '*/*',
                'accept-language': 'en,en-US;q=0.9',
                'origin': 'https://tokcounter.com',
                'priority': 'u=1, i',
                'referer': 'https://tokcounter.com/',
                'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
            }
            
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'views': result.get('viewCount', 0),
                        'likes': result.get('likeCount', 0),
                        'comments': result.get('commentCount', 0),
                        'shares': result.get('shareCount', 0)
                    }
            
            return {
                'views': random.randint(100000, 10000000),
                'likes': random.randint(1000, 500000),
                'comments': random.randint(100, 50000),
                'shares': random.randint(50, 25000)
            }
            
        elif 'youtube.com' in url or 'youtu.be' in url:
            api_url = 'https://tubepilot.ai/wp-admin/admin-ajax.php'
            data = {
                'action': 'yt_data_viewer',
                'yt_url': url
            }
            
            response = requests.post(api_url, data=data, timeout=10)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Updated regular expressions for robust parsing
                views_match = re.search(r"✦ <b>Views Count:</b>\s*([\d,]+)<br>", html_content)
                likes_match = re.search(r"✦ <b>Likes Count:</b>\s*([\d,]+)<br>", html_content)
                comments_match = re.search(r"✦ <b>Comments Count:</b>\s*([\d,]+)<br>", html_content)
                
                # Capture title, handling newlines and whitespace
                title_match = re.search(r"✦ <b>Video Title:</b>\s*([^<]+)<br>", html_content, re.DOTALL)
                
                # Capture description, handling newlines and non-breaking spaces
                description_match = re.search(r"<b>\s*Video\s*Description:</b>\s*<span[^>]*>(.*?)<\/span>", html_content, re.DOTALL)
                
                thumbnail_match = re.search(r"✦ High Quality</span>\s*<a href='(.*?)'", html_content)

                views = int(views_match.group(1).replace(',', '')) if views_match else 0
                likes = int(likes_match.group(1).replace(',', '')) if likes_match else 0
                comments = int(comments_match.group(1).replace(',', '')) if comments_match else 0
                
                title = title_match.group(1).strip() if title_match else 'N/A'
                description = description_match.group(1).strip() if description_match else 'N/A'
                thumbnail = thumbnail_match.group(1).strip() if thumbnail_match else 'N/A'
                
                return {
                    'views': views,
                    'likes': likes,
                    'comments': comments,
                    'shares': random.randint(10, 1000),
                    'title': title,
                    'description': description,
                    'thumbnail_high_quality': thumbnail
                }
            
        return {
            'views': random.randint(1000, 100000),
            'likes': random.randint(10, 5000),
            'comments': random.randint(5, 500),
            'shares': random.randint(1, 100)
        }
        
    except Exception as e:
        return {
            'views': random.randint(1000, 100000),
            'likes': random.randint(10, 5000),
            'comments': random.randint(5, 500),
            'shares': random.randint(1, 100)
        }

def ai_prediction_engine(post_id, target_virality):
    base_odds = min(max(target_virality / 10000.0, 0.2), 0.8)
    content_hash = int(hashlib.md5(post_id.encode()).hexdigest()[:8], 16)
    variance = (content_hash % 100) / 1000.0
    return min(max(base_odds + variance, 0.2), 0.8)

def resolve_expired_markets():
    """
    Finds and resolves all markets that have passed their betting window.
    """
    markets_to_settle = Market.query.filter_by(status='active').all()
    
    for market in markets_to_settle:
        # Check if the market window has closed
        if datetime.utcnow() > market.created_at + timedelta(hours=market.virality_window_hours):
            print(f"Market {market.id} window has closed. Resolving...")
            
            # Fetch the final virality (views) of the video
            final_stats = fetch_video_stats(market.video.url)
            final_views = final_stats['views']
            
            # Determine the winner based on final virality
            winning_prediction = 'over' if final_views >= market.target_virality else 'under'

            # Iterate over all bets for this market and update the winner status
            bets_to_update = Bet.query.filter_by(market_id=market.id).all()
            for bet in bets_to_update:
                if bet.prediction == winning_prediction:
                    bet.is_winner = True
                    # Pay out the winning bet
                    user = User.query.get(bet.user_id)
                    if user:
                        payout = bet.amount * market.initial_odds
                        user.balance += payout
                    else:
                        print(f"User with ID {bet.user_id} not found. Skipping payout.")
                else:
                    bet.is_winner = False

            # Update the market status to settled
            market.status = 'settled'
            
    db.session.commit()

def get_cached_market_status(market_id):
    """Get cached market status - VULNERABLE to stale cache race condition"""
    current_time = time.time()
    
    if (market_id not in cache_last_updated or 
        current_time - cache_last_updated[market_id] > 5):
        
        market = Market.query.get(market_id)
        if market:
            market_status_cache[market_id] = market.is_window_closed()
            cache_last_updated[market_id] = current_time
    
    return market_status_cache.get(market_id, True)

def check_referral_bonus(new_user_id, referral_code):
    """
    VULNERABILITY 1: Referral Program Abuse - Case-sensitive validation bypass
    """
    new_user = User.query.get(new_user_id)
    referrer = User.query.filter(User.referral_code.ilike(referral_code)).first()
    
    if referrer and new_user:
        if new_user.user_agent == referrer.user_agent:
            
            print(f"Referral abuse detected: {new_user.username} -> {referrer.username}")
            return

        else:
            referrer.balance += 100.0
            db.session.commit()
            print(f"Referral bonus awarded: 100 ViralCreds to {referrer.username}")
            
def make_internal_config_request(config_source, csrf_token):
    """Make POST request to load configuration"""
    try:
        base_url = 'http://127.0.0.1:5000'
        internal_url = f"{base_url}/api/config/{config_source}"
        
        session_cookie = request.cookies.get('session')
        
        headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf_token
        }
        
        cookies = {'session': session_cookie} if session_cookie else {}
        
        response = requests.post(
            internal_url,
            headers=headers,
            cookies=cookies,
            json={'config_type': config_source},
            timeout=5
        )
        
        return response.json() if response.status_code == 200 else None
            
    except:
        return None
        
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf_protect
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        referred_by = request.form.get('ref', '')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Store user agent for referral validation
        user_agent = request.headers.get('User-Agent', '')
        
        # Generate verification code
        verification_code = generate_verification_code()
        
        # Create new user (unverified)
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            referral_code=generate_referral_code(),
            referred_by=referred_by if referred_by else None,
            user_agent=user_agent,
            verification_code=verification_code,
            is_verified=False
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        
        # VULNERABILITY 2: Leak verification code in JSON response
        return jsonify({
            'success': True, 
            'message': 'Registration successful! Please check your email for verification code.',
            'user_id': user.id,
            'debug_verification_code': verification_code
        })
    
    return render_template('register.html')

@app.route('/verify_email/<int:user_id>', methods=['GET', 'POST'])
@csrf_protect
def verify_email(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_verified:
        flash('Account already verified!', 'info')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form['verification_code']
        
        if code == user.verification_code:
            user.is_verified = True
            user.verification_code = None
            
            # Process referral bonus after verification
            if user.referred_by:
                check_referral_bonus(user.id, user.referred_by)
            
            db.session.commit()
            flash('Email verified successfully! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code!', 'error')
    
    return render_template('verify_email.html', user=user)
    
@app.route('/resend_verification_code', methods=['POST'])
@csrf_protect
def resend_verification_code():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.is_verified:
        return jsonify({'error': 'User already verified'}), 400

    # Generate a new code and save it
    new_code = generate_verification_code()
    user.verification_code = new_code
    db.session.commit()

    # ⚠️ For now, leak the code in response (consistent with existing vuln design)
    return jsonify({
        'success': True,
        'message': 'Verification code resent. Please check your email.',
        'debug_verification_code': new_code
    })


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        
        if not user.is_verified:
            flash('Please verify your email before logging in.', 'error')
            return redirect(url_for('verify_email', user_id=user.id))
        
        if user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    resolve_expired_markets() 
    user = User.query.get(session['user_id'])
    recent_bets_query = Bet.query.filter_by(user_id=user.id).order_by(Bet.created_at.desc()).limit(10).all()

    # Convert SQLAlchemy Bet objects to dictionaries for JSON serialization
    recent_bets_data = []
    for bet in recent_bets_query:
        bet_data = {
            'id': bet.id,
            'amount': bet.amount,
            'prediction': bet.prediction,
            'potential_payout': bet.potential_payout,
            'is_winner': bet.is_winner,
            'is_claimed': bet.is_claimed,
            'created_at': bet.created_at.isoformat()
        }
        recent_bets_data.append(bet_data)
    
    return render_template('dashboard.html', user=user, recent_bets=recent_bets_data)

@app.route('/api/deposit', methods=['POST'])
@csrf_protect
def api_deposit():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    amount = float(data.get('amount', 0))
    
    user = User.query.get(session['user_id'])
    user.balance += amount
    db.session.commit()
    
    return jsonify({'success': True, 'new_balance': user.balance})

@app.route('/market')
def market():
    resolve_expired_markets()
    markets = Market.query.options(joinedload(Market.video)).all()
    videos = Video.query.all()
    return render_template('market.html', markets=markets, videos=videos, now=datetime.utcnow(), timedelta=timedelta)

@app.route('/api/create_market', methods=['POST'])
@csrf_protect
def api_create_market():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    post_id = data.get('post_id')
    target_virality = int(data.get('target_virality'))
    
    # Get the user-defined virality window, default to 24 hours if not provided
    virality_window_hours = int(data.get('virality_window_hours', 24))
    
    
    # Find the video object using the post_id (URL)
    video = Video.query.filter_by(url=post_id).first()
    
    # If the video is not found, return an error
    if not video:
        return jsonify({'error': 'Video not found.'}), 404

    initial_odds = ai_prediction_engine(post_id, target_virality)
    
    market = Market(
        creator_id=session['user_id'],
        video_id=video.id,
        post_id=post_id,
        target_virality=target_virality,
        initial_odds=initial_odds,
        virality_window_hours=virality_window_hours  # Pass the new value to the model
    )
    
    db.session.add(market)
    db.session.commit()
    
    return jsonify({'success': True, 'market_id': market.id})

@app.route('/api/place_bet', methods=['POST'])
@csrf_protect
def api_place_bet():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    market_id = int(data.get('market_id'))
    amount = float(data.get('amount'))
    prediction = data.get('prediction')
    
    user = User.query.get(session['user_id'])
    market = Market.query.get(market_id)
    
    if user.balance < amount:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    if prediction == 'over':
        potential_payout = amount * (1 / market.initial_odds)
    else:
        potential_payout = amount * (1 / (1 - market.initial_odds))
    
    bet = Bet(
        user_id=user.id,
        market_id=market_id,
        amount=amount,
        prediction=prediction,
        potential_payout=potential_payout
    )
    
    user.balance -= amount
    db.session.add(bet)
    db.session.commit()
    
    return jsonify({'success': True, 'bet_id': bet.id})

@app.route('/api/cancel_bet/<int:bet_id>', methods=['POST','DELETE']) # Can be reached via CSPT2CSRF to cancel bet
@csrf_protect
def api_cancel_bet(bet_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    bet = Bet.query.get_or_404(bet_id)
    
    if bet.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized action'}), 403
    
    market = Market.query.get(bet.market_id)
    
    # VULNERABILITY 3: Stale Cache Race Condition
    is_window_closed_cached = get_cached_market_status(market.id)
    
    if is_window_closed_cached:
        return jsonify({'error': 'Cannot cancel bet - market window has closed'}), 400
    
    refund_amount = bet.amount * 0.9
    user = User.query.get(session['user_id'])
    user.balance += refund_amount
    
    db.session.delete(bet)
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Bet cancelled. Refund of {refund_amount} ViralCreds processed.',
        'new_balance': user.balance
    })

@app.route('/claim_winnings', methods=['POST'])
@csrf_protect
def claim_winnings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    bet_id = int(request.form['bet_id'])
    bet = Bet.query.get(bet_id)
    
    if bet.user_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('dashboard'))
    
    if not bet.is_winner:
        flash('This bet did not win!', 'error')
        return redirect(url_for('dashboard'))
    
    if bet.is_claimed:
        flash('Winnings already claimed!', 'error')
        return redirect(url_for('dashboard'))
    
    # VULNERABILITY 4: Atomic Operation Failure (Double Claim Race Condition)
    user = User.query.get(session['user_id'])
    
    # First operation: Update user balance
    user.balance += bet.potential_payout
    db.session.commit()
    
    # Race condition window here
    time.sleep(0.1)
    
    # Second operation: Mark bet as claimed
    bet.is_claimed = True
    db.session.commit()
    
    # Create a new Transaction record for the payout after the bet is successfully claimed
    transaction = Transaction(
        user_id=user.id,
        amount=bet.potential_payout,
        description=f"Winnings claimed from bet ID: {bet.id}"
    )
    db.session.add(transaction)
    db.session.commit()

    flash(f'Winnings of {bet.potential_payout} ViralCreds claimed successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile():
    """User's own profile page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/api/bettinghistory')
def api_betting_history():
    # VULNERABILITY 5: IDOR in betting history - users can view other users' betting history
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        """No access control - user_id parameter can be manipulated"""
    target_user_id = request.args.get('user_id', session['user_id'])
    
    bets = Bet.query.filter_by(user_id=target_user_id).order_by(Bet.created_at.desc()).all()
    
    betting_history = []
    for bet in bets:
        market = Market.query.get(bet.market_id)
        betting_history.append({
            'id': bet.id,
            'amount': bet.amount,
            'prediction': bet.prediction,
            'potential_payout': bet.potential_payout,
            'is_winner': bet.is_winner,
            'is_claimed': bet.is_claimed,
            'created_at': bet.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'market_post_id': market.post_id if market else 'Unknown',
            'market_target_virality': market.target_virality if market else 0
        })
    
    return jsonify({'bets': betting_history})

@app.route('/submit_video', methods=['GET', 'POST'])
@csrf_protect
def submit_video():
    # VULNERABILITY 6: SSRF + Whitelisting Bypass
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if request.is_json:
            # Handle the AJAX request from the JavaScript for video details
            data = request.get_json()
            url = data.get('url')
            if not url:
                return jsonify({'success': False, 'message': 'Video URL is a required field.'}), 400

            try:
                stats = fetch_video_stats(url)
                if stats.get('views') is None:
                    return jsonify({'success': False, 'message': 'Could not fetch video details.'}), 500
                
                # Return video details as a JSON response
                return jsonify({
                    'success': True,
                    'title': stats.get('title', 'N/A'),
                    'description': stats.get('description', 'N/A')
                })
            except Exception as e:
                return jsonify({'success': False, 'message': f'An unexpected error occurred: {str(e)}'}), 500

        else:
            # Handle the standard form submission
            url = request.form.get('url')
            title = request.form.get('title')
            description = request.form.get('description', '')

            if not url:
                flash('Video URL is a required field.', 'error')
                return render_template('submit_video.html')

            allowed_domains = ['www.youtube.com', 'www.tiktok.com', 'youtube.com', 'tiktok.com', 'youtu.be']
            # Can be bypassed via: youtube.com@127.0.0.1 leading to SSRF
            is_valid_url = any(url.startswith(f'https://{domain}') or url.startswith(f'http://{domain}') for domain in allowed_domains) 
            
            if not is_valid_url:
                flash('URL must be from YouTube or TikTok!', 'error')
                return render_template('submit_video.html')
                
            try:
                resp = requests.get(url, timeout=3) # Check if video exists (SSRF)
                if resp.status_code != 200:
                    flash('Video not found', 'error') 
                    return render_template('submit_video.html')
            except requests.RequestException:
                flash('Could not reach video', 'error')
                return render_template('submit_video.html')
            
            try:
                stats = fetch_video_stats(url)
                
                if stats.get('views') is None:
                    flash('Could not fetch video details. Please check the URL and try again.', 'error')
                    return render_template('submit_video.html')

                if 'youtube.com' in url or 'youtu.be' in url:
                    final_title = stats.get('title', 'N/A')
                    final_description = stats.get('description', 'N/A')
                elif 'tiktok.com' in url:
                    final_title = title
                    final_description = ''
                else:
                    final_title = title
                    final_description = description
                
                if not final_title:
                    flash('Video title is a required field for this platform.', 'error')
                    return render_template('submit_video.html')

                video = Video(
                    url=url,
                    title=final_title,
                    description=final_description,
                    thumbnail=stats.get('thumbnail_high_quality'),
                    submitted_by=session['user_id'],
                    views=stats.get('views', 0),
                    likes=stats.get('likes', 0),
                    comments=stats.get('comments', 0),
                    shares=stats.get('shares', 0)
                )
                
                db.session.add(video)
                db.session.commit()
                
                flash('Video submitted successfully!', 'success')
                return redirect(url_for('videos'))
            
            except Exception as e:
                flash(f'An unexpected error occurred: {str(e)}', 'error')
                return render_template('submit_video.html')
    
    return render_template('submit_video.html')

@app.route('/videos')
def videos():
    """Display submitted videos"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    videos = Video.query.order_by(Video.created_at.desc()).all()
    for video in videos:
        video.description = urllib.parse.unquote(video.description) #VULNERABILITY 7: XSS by uploading a Youtube Video with payload in description
    return render_template('videos.html', videos=videos)

@app.route('/api/update_video_stats', methods=['POST'])
@csrf_protect
def api_update_video_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    video_id = data.get('video_id')
    
    video = Video.query.get(video_id)
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    
    # Fetch updated stats
    stats = fetch_video_stats(video.url)
    
    video.views = stats['views']
    video.likes = stats['likes']
    video.comments = stats['comments']
    video.shares = stats['shares']
    video.last_updated = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'stats': {
            'views': video.views,
            'likes': video.likes,
            'comments': video.comments,
            'shares': video.shares
        }
    })

@app.route('/api/config/notifications', methods=['POST'])
@csrf_protect
def api_config_notifications():
    """Internal endpoint for notification configuration"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'email_notifications': True,
        'push_notifications': False,
        'sms_notifications': False,
        'marketing_emails': True
    })

@app.route('/settings', methods=['GET', 'POST'])
@csrf_protect
def settings():
    """VULNERABILITY: CSPT2CSRF Source - config_source parameter"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            user.first_name = request.form['first_name']
            user.last_name = request.form['last_name']
            user.username = request.form['username']
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        elif action == 'change_email':
            new_email = request.form['new_email']
            
            # Check if email already exists
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already in use'}), 400
            else:
                user.email = new_email
                user.is_verified = False  # Require re-verification
                verification_code = generate_verification_code()
                user.verification_code = verification_code
                
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Email updated! Please verify your new email.',
                    'debug_verification_code': verification_code
                })
    
    # Calculate referral stats to pass to the template
    referred_users = User.query.filter_by(referred_by=user.referral_code).all()
    valid_referrals = []

    for referred_user in referred_users:
        # Check if this referral would pass abuse detection
        if not referred_user.user_agent == user.user_agent:
            valid_referrals.append(referred_user)

    referral_count = len(valid_referrals)
    total_bonus_earned = referral_count * 100            
    
    # CSPT2CSRF Source: User-controlled config_source parameter
    config_source = request.args.get('config_source', 'notifications')
    csrf_token = generate_csrf_token()
    config_data = make_internal_config_request(config_source, csrf_token)

    
    return render_template('settings.html', 
        user=user, 
        config_source=config_source,
        config_data=config_data,
        referral_count=referral_count,
        total_bonus_earned=total_bonus_earned
    )

@app.route('/api/support/chat', methods=['POST'])
@csrf_protect
def api_support_chat():
    user_id = session.get('user_id')
    data = request.get_json()
    message = data.get('message', '').lower()

    # Log the user's message
    user_chat = SupportChat(user_id=user_id, message=message, is_user=True)
    db.session.add(user_chat)
    db.session.commit()

    response_text = ""
    # Check for specific options
    if message == "1" or "balance" in message:
        # Option 1: Account Balance Inquiry (Safe)
        user = User.query.get(user_id)
        if user:
            response_text = f"Your current account balance is: ${user.balance:.2f}"
        else:
            response_text = "Sorry, I could not find your account details."
    elif message == "2" or "invoice" in message:
        # Option 2: Generate Invoice (VULNERABLE)
        transaction = Transaction.query.filter_by(user_id=user_id).order_by(db.desc(Transaction.created_at)).first()
        if transaction:
            response_text = "invoice_request"
        else:
            response_text = "Sorry, I could not find any recent transactions to generate an invoice for."
    elif message == "3" or "stats" in message or "statistics" in message:
        # Option 3: Platform Statistics (Safe)
        user_count = User.query.count()
        market_count = Market.query.count()
        response_text = f"Current Platform Statistics:\n- Total Users: {user_count}\n- Total Markets: {market_count}"
    elif any(greeting in message for greeting in ['hi', 'hello', 'hey', 'yo']):
        response_text = "Hello! I'm the ViralVault support bot. How can I help you today? Please choose from the options below:"
    else:
        response_text = "Sorry, I cannot assist you with that."

    # Log the bot's response
    bot_chat = SupportChat(user_id=user_id, message=response_text, is_user=False)
    db.session.add(bot_chat)
    db.session.commit()
    
    return jsonify({'response': response_text})

@app.route('/api/support/generate_invoice', methods=['POST'])
@csrf_protect
def api_support_generate_invoice():
    html_content = request.get_json().get('html_content')
    if not html_content:
        return jsonify({'error': 'HTML content is required.'}), 400

    try:
        #VULNERABILITY 9: SSRF via HTML To PDF generation
        process = subprocess.run(
            ['wkhtmltopdf', '--enable-local-file-access', '-', '-'],
            input=html_content.encode('utf-8'),
            capture_output=True,
            check=True
        )
        pdf_base64 = base64.b64encode(process.stdout).decode('utf-8')
        return jsonify({
            'status': 'success',
            'pdf_base64': pdf_base64
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            'status': 'error',
            'message': 'PDF generation failed.',
            'details': e.stderr.decode('utf-8')
        }), 500
    except FileNotFoundError:
        return jsonify({
            'status': 'error',
            'message': 'wkhtmltopdf not found. Please ensure it is installed and in your system PATH.'
        }), 500


@app.route('/admin', methods=['GET', 'POST'])
@csrf_protect
def admin():
    """Secure admin panel"""
    ADMIN_PASSWORD = "ultra_secure_admin_password_2024_!@#$%"
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin password!', 'error')
    
    if not session.get('admin_authenticated'):
        return render_template('admin_login.html')
    
    # Admin panel content
    markets = Market.query.order_by(Market.created_at.desc()).limit(20).all()
    users = User.query.order_by(User.created_at.desc()).limit(20).all()
    videos = Video.query.order_by(Video.created_at.desc()).limit(20).all()
    
    return render_template('admin.html', markets=markets, users=users, videos=videos)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@viralvault.com',
                first_name='Admin',
                last_name='User',
                referral_code=generate_referral_code(),
                balance=10000.0,
                is_admin=True,
                is_verified=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        
        # Create sample users for testing
        if not User.query.filter_by(username='alice').first():
            alice = User(
                username='alice',
                email='alice@test.com',
                first_name='Alice',
                last_name='Johnson',
                referral_code=generate_referral_code(),
                balance=1200.0,
                is_verified=True
            )
            alice.set_password('alice123')
            db.session.add(alice)
            print("Sample User alice/alice123 created")
            
        if not User.query.filter_by(username='bob').first():
            bob = User(
                username='bob',
                email='bob@test.com',
                first_name='Bob',
                last_name='Smith',
                referral_code=generate_referral_code(),
                balance=800.0,
                is_verified=True
            )
            bob.set_password('bob456')
            db.session.add(bob)
            print("Sample User bob/bob456 created")
            
        # Create sample videos
        if not Video.query.first():
            sample_videos = [
                {
                    'url': 'https://www.youtube.com/watch?v=gSJeHDlhYls',
                    'title': 'Madvillain - All Caps',
                    'description': 'MF DOOM and Madlib are Madvlllain',
                    'submitted_by': 2
                },
                {
                    'url': 'https://www.youtube.com/watch?v=3wbFjrbU1t4',
                    'title': 'E. Coli',
                    'description': 'E. Coli · The Alchemist · Earl Sweatshirt',
                    'submitted_by': 3
                }
            ]
            
            for video_data in sample_videos:
                stats = fetch_video_stats(video_data['url'])
                video = Video(
                    url=video_data['url'],
                    title=video_data['title'],
                    description=video_data['description'],
                    submitted_by=video_data['submitted_by'],
                    thumbnail=stats.get('thumbnail_high_quality'),
                    views=stats['views'],
                    likes=stats['likes'],
                    comments=stats['comments'],
                    shares=stats['shares']
                )
                db.session.add(video)
        db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
