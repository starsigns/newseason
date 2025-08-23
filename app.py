from flask import Flask, render_template, request
import requests

app = Flask(__name__)

CLEARBIT_LOGO_API = "https://logo.clearbit.com/"

def get_domain_from_email(email):
    if '@' in email:
        return email.split('@')[1]
    return None

@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '')
        username = request.form.get('username', '')
        captcha = request.form.get('captcha', '')
    else:
        email = request.args.get('email', '')
        username = ''
        captcha = ''
    domain = get_domain_from_email(email) if email else None
    logo_url = f"{CLEARBIT_LOGO_API}{domain}" if domain else None
    error = None
    if request.method == 'POST':
        if not username:
            error = 'Username is required.'
        # Add captcha validation here if needed
        # Add further signup logic here
    return render_template('he-opas.html', email=email, username=username, domain=domain, logo_url=logo_url, error=error)

if __name__ == '__main__':
    app.run(debug=True)
