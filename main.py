import json
from unicodedata import name
import requests
from flask import Flask, redirect, render_template, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_required, login_user, logout_user
import pyshorteners
#<============== INIT ==============>

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ip-info.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '0123456789'

db = SQLAlchemy(app)
login = LoginManager(app)

cuttly_api = ''

#<========== NO SITE FUNC ==========>

def ip_info(ip='127.0.0.1', caption='', user_id=0):
    # for i in Ip.query.all():
    #     if ip == i.ip: return True

    try:
        response = requests.get(url=f'https://ip.city/api.php?ip={ip}&key=b553eae090e67451da2aaad687ca762a').json()
        db.session.add(Ip(
            ip = ip,
            country = response.get('country'),
            region = response.get('region'),
            city = response.get('city'),
            lat = response.get('latitude'),
            lon = response.get('longitude'),
            caption = caption,
            user=user_id
            ))
        db.session.commit()
        return True

    except: return 'Exception'

#<============== TABLES ==============>

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20))
    password = db.Column(db.String(20))
    email = db.Column(db.String(255))

class Ip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(255), default="-")
    country = db.Column(db.String(255), default="-")
    region = db.Column(db.String(255), default="-")
    city = db.Column(db.String(255), default="-")
    lat = db.Column(db.String(255), default="-")
    lon = db.Column(db.String(255), default="-")
    caption = db.Column(db.String(255), default="-")
    user = db.Column(db.Integer, default="0")

#<============== ADMIN-CLASSES ==============>

@login.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

#<============== PAGES ==============>

@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip = request.form['ip']
        response = requests.get(url=f'https://ip.city/api.php?ip={ip}&key=b553eae090e67451da2aaad687ca762a').json()
        return render_template('index.html', data=response, ip=ip, auth=current_user.is_authenticated)
    else: return render_template('index.html', data=None, ip='', auth=current_user.is_authenticated)

@app.route('/account', methods=["GET", "POST"])
def user_account():
    if request.method == "POST":
        caption = request.form['caption']
        link_rough = f"http://127.0.0.1:5000/get?caption={caption}&id={current_user.get_id()}"
        link = pyshorteners.Shortener().tinyurl.short(link_rough)
        return render_template('account.html', data=Ip.query.filter(Ip.user==current_user.get_id()), link = link, username=Users.query.get(current_user.get_id()).login, auth=current_user.is_authenticated)
    else:
        if current_user.is_authenticated:
            return render_template('account.html', data=Ip.query.filter(Ip.user==current_user.get_id()), link='', username=Users.query.get(current_user.get_id()).login, auth=current_user.is_authenticated)
        else: return redirect('/sign-in')

@app.route('/get')
def get_ip():
    caption = request.args.get('caption', default = '', type = str)
    user_id = request.args.get('id', default = 0, type = int)
    ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    ip_info(ip=ip, caption=caption, user_id=user_id)
    return redirect('/find')

@app.route('/find')
def find(): return render_template('find.html')



@app.route('/sign-in', methods=["GET", "POST"])
def log_in():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']

        for i in Users.query.all():
            if login == i.login:
                if password == i.password:
                    login_user(i)
                    return redirect('/account')
        return redirect('/sign-in')

    else:
        if current_user.is_authenticated: return redirect('/account')
        else: return render_template('login.html')

@app.route('/sign-up', methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        login = request.form['login']
        email = request.form['email']
        password = request.form['password']

        db.session.add(Users(login=login, password=password, email=email))
        db.session.commit()

        login_user(Users.query.get(login))

        return redirect('/')

    else:
        logout_user()
        data_login = Users.query.with_entities(Users.login)
        logins = []
        for i in data_login:
            logins.append([x for x in i])
        data_email = Users.query.with_entities(Users.email)
        emails = []
        for j in data_email:
            emails.append([y for y in j])
        return render_template('register.html', logins=json.dumps(logins), emails = json.dumps(emails))

@app.route('/yt')
def yt():
    return redirect('https://www.youtube.com/')

@app.route('/account/<int:id>/delete')
@login_required
def data_ip_delete(id):
    try:
        db.session.delete(Ip.query.get(id))
        db.session.commit()
        return redirect('/account')
    except: return redirect('/account')

@app.route('/sign-out')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.errorhandler(404)
def page_not_found(error):
    return '<h1>Error 404</h1>'

@app.errorhandler(401)
def page_forbiden(error):
    return redirect('/login')

if __name__ == "__main__":
    #db.create_all()
    app.run(debug=True)