# ViralVault: Walkthrough

## Introduction
ViralVault is a web application security lab designed to provide a hands-on learning experience for bug bounty hunters and security researchers. The platform simulates a social media virality betting platform, containing several intentionally planted vulnerabilities. This document serves as a guide to the lab's challenges, detailing the vulnerabilities, how to exploit them, and how to fix them.

## Challenges
Each challenge corresponds to a specific vulnerability. The goal is to find and exploit these vulnerabilities to understand their impact and learn how to mitigate them. The vulnerabilities are listed below in the order they appear in the source code. 

I wanted to keep things realistic, so some exploitation steps can be annoying. Which is indeed, realistic.

---

### Challenge 1: Referral Program Abuse

* **Vulnerability:** A User-Agent validation bypass in the referral program. A new user can use an altered version of their User-Agent to claim a bonus by creating multiple accounts.
* **Location:** The `check_referral_bonus` function in `app.py`.
* **Exploitation:**
    1.  Create a user account (e.g., `user1`) and get their referral code (e.g., `ABCDE123`).
    2.  Create a second user account (e.g., `user2`) and, during registration, use an altered User-Agent.
    3.  `user1` will receive the bonus and can repeat the process themself to receive multiple bonuses.
* **Fix:** Use multiple validation cases such as IP address and/or set limit on how many referrals a user can have.
* **Fixed Code:**
```python
if referrer and new_user:
        # Check for user agent AND IP address match
        if (new_user.ip_address == referrer.ip_address and new_user.user_agent == referrer.user_agent):
            print(f"Referral abuse detected: {new_user.username} -> {referrer.username}")
            return
        
        # Check if referrer has reached their referral limit
        referral_count = User.query.filter_by(referred_by=referrer.referral_code).count()
        if referral_count >= 10:  # Example limit
            print(f"Referral limit reached for user: {referrer.username}")
            return
            
        referrer.balance += 100.0
        db.session.commit()
        print(f"Referral bonus awarded: 100 ViralCreds to {referrer.username}")

```


### Challenge 2: Leak Verification Code

* **Vulnerability:** The account verification code is returned in the JSON response during the registration process.
* **Location:** The `/register` route in `app.py`.
* **Exploitation:**
    1.  Intercept the JSON response from a user's registration request.
    2.  Extract the `debug_verification_code` from the response.
    3.  Use this code to verify the account at the `/verify_email` endpoint without needing to check an email.
* **Fix:** Remove the `debug_verification_code` from the JSON response.
* **Fixed Code:**
```python
 send_verification_email(email, verification_code)
        
        # VULNERABILITY 2: Leak verification code in JSON response
        return jsonify({
            'success': True, 
            'message': 'Registration successful! Please check your email for verification code.',
            'user_id': user.id 
            # removed 'debug_verification_code': verification_code
        })
```

### Challenge 3: Stale Cache Race Condition

* **Vulnerability:** A race condition where a bet can be canceled after its market has closed, due to a stale cache. The application checks a cached market status that can be outdated, allowing an attacker to submit a cancellation request in the brief window between the market closing and the cache updating. This can also be exploited for a different, undocumented purpose...
* **Location:** The `api_cancel_bet` function in `app.py`.
* **Exploitation:**
    1.  Place a bet on a market that is about to close.
    2.  Use a race condition tool (e.g., Burp Suite's single-packet attack or Turbo Int) to send a rapid series of `POST` requests to the `/api/cancel_bet` endpoint as the market closes.
    3.  If successful, one of the requests will slip through and cancel the bet, refunding your money even though the market has already closed.
* **Fix:** Use a reliable, real-time check of the market status from the database or a synchronized global state instead of a time-based cache that can become stale. Ensure all critical checks are performed atomically.
* **Fixed Code:**
```python
 
    # VULNERABILITY 3: Stale Cache Race Condition
    # removed cached market status: is_window_closed_cached = get_cached_market_status(market.id) and added real time check
    
    market = Market.query.get(bet.market_id)
    if market.status != 'open':
        return jsonify({'error': 'Market is already closed'}), 400

    
    refund_amount = bet.amount * 0.9
    user = User.query.get(session['user_id'])
    user.balance += refund_amount
    
    db.session.delete(bet)
    db.session.commit()
```

### Challenge 4: Double Claim Race Condition

* **Vulnerability:** A race condition in the winnings claim process. The application updates the user's balance and then, after a brief delay, marks the winnings as claimed. An attacker can exploit this delay by sending two concurrent requests to claim the same winnings, receiving the payout twice.
* **Location:** The `claim_winnings` function in `app.py`.
* **Exploitation:**
    1.  Place a winning bet.
    2.  Use a race condition tool (e.g., Burp Suite's Turbo Intruder) to send two or more concurrent `POST` requests to the `/claim_winnings` endpoint.
    3.  The race condition will allow both requests to pass the `is_claimed` check before the first one completes, resulting in a double payout.
* **Fix:** Use a database transaction to ensure the balance update and the `is_claimed` flag are updated atomically. This prevents the race condition by locking the record during the update process.
* **Fixed Code:**
```python
try:
        # Use a transaction to ensure atomicity
        db.session.begin()
        
        user = User.query.get(session['user_id'])
        user.balance += bet.winnings
        bet.is_claimed = True
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f"Winnings of {bet.winnings} ViralCreds claimed!"
        })

```

### Challenge 5: Insecure Direct Object Reference (IDOR)

* **Vulnerability:** The `api_betting_history` endpoint allows a user to specify a `user_id` in the URL query parameters. The application then retrieves the betting history for that `user_id` without checking if the authenticated user (`session['user_id']`) has permission to view it.
* **Location:** The `api_betting_history` endpoint in `app.py`.
* **Exploitation:**
    1.  Log in to the application.
    2.  Navigate to the `/api/bettinghistory?user_id=X` endpoint, where `X` is the ID of a user whose betting history you want to view.
    3.  The application will return the betting history for user `X` without checking if you are authorized to view it.
* **Fix:** Ensure that the authenticated user's ID (`session['user_id']`) is used for all database queries involving user data, and never trust a `user_id` provided in the request parameters.
* **Fixed Code:**
```python
if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    user_id = session['user_id']
    
    bets = Bet.query.filter_by(user_id=user_id).order_by(Bet.timestamp.desc()).all()
```

### Challenge 6: SSRF via Whitelisting Bypass

* **Vulnerability:** The video submission form attempts to whitelist URLs to prevent Server-Side Request Forgery (SSRF). However, the whitelist is poorly implemented and can be bypassed using the `@` character in a URL.
* **Location:** The `submit_video` function in `app.py`.
* **Exploitation:**
    1.  Submit a URL like `http://youtube.com@127.0.0.1/` to the `/submit_video` endpoint.
    2.  The application's whitelisting will see `youtube.com` and approve the URL.
    3.  The `requests.get` call will then be directed to `127.0.0.1`, allowing you to make a request to an internal resource.
* **Fix:** Implement a robust URL validation that correctly parses and checks the hostname of the URL, or use a dedicated library for URL validation. Do not rely on simple string-based checks.
* **Fixed Code:**
```python
# We can create a seprate function to validate urls:
def is_safe_url(url):
    try:
        parsed = urlparse(url)
        
        # Check scheme to prevent usage of other protocols such as file, gopher etc...
        if parsed.scheme not in ['http', 'https']: 
            return False
        
        
        # Extract hostname
        hostname = parsed.hostname
        if not hostname:
            return False
        
        # Whitelist check - exact domain matching
        allowed_domains = [
            'www.youtube.com', 
            'youtube.com', 
            'youtu.be',
            'www.tiktok.com', 
            'tiktok.com'
        ]
        
        if hostname not in allowed_domains:
            return False
        
        # Resolve hostname to IP and check for private/local addresses
        try:
            ip_addresses = socket.getaddrinfo(hostname, None)
            for addr_info in ip_addresses:
                ip = addr_info[4][0]
                ip_obj = ipaddress.ip_address(ip)
                
                # Block private, loopback, and reserved IP ranges
                if (ip_obj.is_private or 
                    ip_obj.is_loopback or 
                    ip_obj.is_reserved or
                    ip_obj.is_multicast or
                    ip_obj.is_link_local):
                    return False
                    
        except (socket.gaierror, ValueError):
            return False
        
        return True
        
    except Exception:
        return False
```

### Challenge 7: Cross-Site Scripting (XSS)

* **Vulnerability:** The application does not sanitizes video descriptions before rendering them in the HTML. This can be exploited by submitting a URL-encoded XSS payload as part of the description.
* **Location:** The `/videos` route in `app.py`.
* **Exploitation:**
    1.  Create a YouTube video and, in its description, include a URL-encoded XSS payload (e.g., `%3Cscript%3Ealert(document.cookie)%3C/script%3E`).
    2.  Submit the video to the ViralVault platform.
    3.  When the `/videos` page is viewed, the payload will be unquoted and rendered as executable JavaScript, triggering the XSS.
* **Fix:** Always use a templating engine's auto-escaping features to prevent the rendering of untrusted data as HTML. (for the sake of the lab `urllib.parse.unquote` was used on the description field since Youtube does not allows normal HTML tags in the description or title.) The fix is to simply not unquote/decode HTML tags manually. Of course, in other cases the fix can be to escape HTML tags.
* **Fixed Code:**
```python
@app.route('/videos')
def videos():
    """Display submitted videos"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    videos = Video.query.order_by(Video.created_at.desc()).all()
    """
    for video in videos:
        video.description = urllib.parse.unquote(video.description) was removed
    """ 
    return render_template('videos.html', videos=videos)
```
### Challenge 8: Client Side Path Traversal to Cross Site Request Forgery (CSPT2CSRF)

* **Vulnerability:** The `settings` page includes a Client Side Path Traversal vulnerability through the `config_source` that can be further escalated to a CSRF attack to cancel bets. It's a two-step process where the GET request triggers a POST request with data from the GET request. the first GET request is made to `/settings?config_source=../cancel_bet/1` which triggers a POST request to `/api/config/../cancel_bet/1` due to the path traversal the POST request is made to `/api/cancel_bet/1` cancelling the bet, since the request is technically made by the server it includes the CSRF token, which bypasses the CSRF token requirement. I would highly recommend reading this Whitepaper by Doyensec: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf
* **Location:** The `/settings` route and `make_internal_config_request` function  in `app.py`.
* **Exploitation:** append `config_source` parameter to `/settings` which can be used to traverse to `../cancel_bet/{id}` leading to cancelation of the bet, making the final path: `/settings?config_source=../cancel_bet/1` the `config_source` parameter is normally used to fetch notification preferences of the user by making a POST request to `/api/config/notifications` However, due to our path traversal it makes a POST request to `/api/cancel_bet/1`
* **Fix:** Instead of allowing user-controlled paths, use a mapping which basically acts as a whitelist.
* **Fixed Code:**
```python
CONFIG_ENDPOINTS = {
    'notifications': '/api/config/notifications',
    'otherendpoints': '/api/config/otherendpoints',
    'otherendpoints': '/api/config/otherendpoints',
    'otherendpoints': '/api/config/otherendpoints'
}

def make_internal_config_request(config_source, csrf_token):
    """Make POST request to load configuration - using server-side URL mapping"""
    try:
        # Get the endpoint from our predefined mapping
        # If config_source is not in mapping, this returns None
        endpoint_path = CONFIG_ENDPOINTS.get(config_source)
        
        if not endpoint_path:
            # Invalid config_source - return None instead of making request
            return None
            
        base_url = 'http://127.0.0.1:5000'
        # Use the mapped endpoint
        internal_url = f"{base_url}{endpoint_path}"
        
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
            
    except Exception:
        return None

@app.route('/settings', methods=['GET', 'POST'])
@csrf_protect
def settings():
...rest of the code...
    config_source = request.args.get('config_source', 'notifications')
    
    # Check if the requested config_source exists in our mapping
    if config_source not in CONFIG_ENDPOINTS:
        # Use default safe value if not in mapping
        config_source = 'notifications'
    
    csrf_token = generate_csrf_token()
    config_data = make_internal_config_request(config_source, csrf_token)
    
    return render_template('settings.html', 
        user=user, 
        config_source=config_source,
        config_data=config_data,
        referral_count=referral_count,
        total_bonus_earned=total_bonus_earned,
        available_configs=list(CONFIG_ENDPOINTS.keys())  # Pass available configs to template
    )

```

### Challenge 9: SSRF via PDF Generation

* **Vulnerability:** The application uses `wkhtmltopdf` with the `--enable-local-file-access` flag to convert user-supplied HTML to a PDF. This dangerous configuration allows an attacker to read local files from the server. This can be also exploited for a different undocumented vulnerability...
* **Location:** The `api_support_generate_invoice` function in `app.py`.
* **Exploitation:**
    1.  Send a POST request to `/api/support/generate_invoice` with HTML containing a malicious payload, such as an `<img>` tag with a `file://` URI. For example: `{"html_content": "<img src="file:///C:/Program Files/Internet Explorer/images/bing.ico">"}`.
    2.  `wkhtmltopdf` will attempt to render this image, which will cause it to read the `C:/Program Files/Internet Explorer/images/bing.ico` file and embed it into the generated PDF.
* **Fix:** Sanitize user input html and never use the `--enable-local-file-access` flag with `wkhtmltopdf`. If file access is necessary, use a secure, sandboxed environment for the PDF generation process. A whitelist is a good idea as i've seen HTML escaping being implemented. However, an attacker can simply intercept the request and decode the HTML tags and there is no reason to allow any other HTML tags since the invoice follows a pre-defined template.
* **Fixed Code**:
```python
# Whitelist of allowed HTML tags and their permitted attributes
ALLOWED_TAGS = {
    'div': ['style'],
    'h2': ['style'], 
    'p': ['style'],
    'hr': ['style'],
    'strong': []
}

def validate_html_content(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check all elements in the HTML
        for element in soup.find_all():
            tag_name = element.name.lower()
            
            # Check if tag is allowed
            if tag_name not in ALLOWED_TAGS:
                return False, f"Disallowed HTML tag: <{tag_name}>"
            
            # Check if attributes are allowed for this tag
            allowed_attrs = ALLOWED_TAGS[tag_name]
            for attr_name in element.attrs:
                if attr_name.lower() not in allowed_attrs:
                    return False, f"Disallowed attribute '{attr_name}' in <{tag_name}>" 
                 #tbh, this provides the attacker a hint on the kind of mitigation implemented, which should be prevented.
        
        return True, "Valid HTML"
        
    except Exception as e:
        return False, f"HTML parsing error: {str(e)}"

@app.route('/api/support/generate_invoice', methods=['POST'])
@csrf_protect
def api_support_generate_invoice():
    """PDF generation with HTML tag whitelist"""
    
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required.'}), 401
    
    html_content = request.get_json().get('html_content')
    if not html_content:
        return jsonify({'error': 'HTML content is required.'}), 400
    
    # Check allowed tags
    is_valid, error_message = validate_html_content(html_content)
    if not is_valid:
        return jsonify({'error': 'Invalid HTML content', 'details': error_message}), 400
    
    try:
        process = subprocess.run(
            ['wkhtmltopdf', '--disable-local-file-access', '--disable-javascript', '--disable-external-links',  '-', '-'], 
            # Disabled local file access, javascript and requests to external links for enhanced security
            input=html_content.encode('utf-8'),
            capture_output=True,
            check=True,
            timeout=30
        )
        pdf_base64 = base64.b64encode(process.stdout).decode('utf-8')
        return jsonify({'status': 'success', 'pdf_base64': pdf_base64})
        
    except subprocess.CalledProcessError as e:
        return jsonify({
            'status': 'error',
            'message': 'PDF generation failed.',
            'details': e.stderr.decode('utf-8')
        }), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'PDF generation timed out.'}), 500
    except FileNotFoundError:
        return jsonify({
            'status': 'error',
            'message': 'wkhtmltopdf not found. Please ensure it is installed.'
        }), 500
