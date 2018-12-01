from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from startup_setup import Startup, Base, Founder, User
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Startup Application'

engine = create_engine('sqlite:///startup.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'
                                            ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps('''Failed to upgrade the
                                        authorization code.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = \
            make_response(json.dumps('''Token's user ID doesn't
                          match given user ID.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps('''Token's client ID does not
                                     match app's.'''), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('''Current user is
                            already connected.'''), 200)
        response.headers['Content-Type'] = 'application/json'

    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ''' " style = "width: 300px;
        height: 300px;border-radius: 150px;
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '''
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'
                                                             ]).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['gplus_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = redirect(url_for('showstartups'))
        flash('You are now logged out.')
        return response
    else:
        response = \
            make_response(json.dumps('Failed to revoke token for given user.',
                                     400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
@app.route("/startups")
def showstartups():
	startups = session.query(Startup).all()
	if 'username' not in login_session:
		return render_template('publicstartup.html', startups = startups)
	else:
		return render_template('startup.html', startups = startups)
	# return "This will show startups"

@app.route("/startups/<int:startup_id>/founders", methods=['GET', 'POST'])
def showfounder(startup_id):
	startup_1 = session.query(Startup).filter_by(id=startup_id).one()
	details = session.query(Founder).filter_by(startup_id=startup_id).all()
	creator = getUserInfo(startup_1.user_id)
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('publicfounders.html', startup_1=startup_1, details=details, creator=creator)
	else:
		if request.method == 'POST':
			newsfounder = Founder(name=request.form['name'], bio=request.form['bio'], startup_id=startup_id, user_id=login_session['user_id'])
			session.add(newsfounder)
			session.commit()
			flash("Founder Added successfully")
			return redirect(url_for('showfounder', startup_id=startup_id))
		else:
			return render_template('founders.html', startup_1=startup_1, details=details, creator=creator)
	
		
	# return "This page will show founders"
@app.route("/startups/<int:founder_id>/edit/founder", methods=['GET', 'POST'])
def editfounder(founder_id):
	editfounder = session.query(Founder).filter_by(id=founder_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if editfounder.user_id != login_session['user_id']:
		return redirect(url_for('showfounder', startup_id=editfounder.startup_id))
	if request.method == 'POST':
		if request.form['name']:
			editfounder.name = request.form['name']
		if request.form['bio']:
			editfounder.bio = request.form['bio']
		session.add(editfounder)
		session.commit()
		flash("Founder Edited successfully")
		return redirect(url_for('showfounder', startup_id=editfounder.startup_id))
	else:
		return render_template('editfounder.html', edit=editfounder)

@app.route("/startups/<int:founder_id>/delete/founder", methods=['GET', 'POST'])
def deletefounder(founder_id):
	deletefounder = session.query(Founder).filter_by(id=founder_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if deletefounder.user_id != login_session['user_id']:
		return redirect(url_for('showfounder', startup_id=deletefounder.startup_id))
	if request.method == 'POST':
		session.delete(deletefounder)
		session.commit()
		flash("Founder Deleted successfully")
		return redirect(url_for('showfounder', startup_id=deletefounder.startup_id))
	else:
		return render_template('deletefounder.html', delete=deletefounder)


@app.route("/startups/new", methods=['GET', 'POST'])
def newstartup():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		newstartup = Startup(name=request.form['name'], user_id=login_session['user_id'])
		session.add(newstartup)
		session.commit()
		flash("Startup Added successfully")
		return redirect(url_for('showstartups'))
	else:
		return render_template('newstartup.html')
	# return "This page will cretae a new startup"

@app.route("/startups/<int:startupid>/edit", methods=['GET', 'POST'])
def editstartup(startupid):
	editedstartup = session.query(Startup).filter_by(id=startupid).one()
	if 'username' not in login_session:
		return redirect('/login')
	if editedstartup.user_id != login_session['user_id']:
		return redirect(url_for('showfounder', startup_id=startupid))
	if request.method == 'POST':
		if request.form['name']:
			editedstartup.name = request.form['name']
		session.add(editedstartup)
		session.commit()
		flash("Startup Edited successfully")
		return redirect(url_for('showfounder', startup_id=startupid))
	else:
		return render_template('editstartup.html', edit=editedstartup)

	# return "This page is used to edit startup id"

@app.route("/startups/<int:startup_id>/delete", methods=['GET', 'POST'])
def deletestartup(startup_id):
	delstartup = session.query(Startup).filter_by(id=startup_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if restaurantToDelete.user_id != login_session['user_id']:
		return redirect(url_for('showstartups'))
	if request.method == 'POST':
		session.delete(delstartup)
		session.commit()
		flash("Startup Deleted successfully")
		return redirect(url_for('showstartups'))
	else:
		return render_template('deletestartup.html', delstartup=delstartup)
	# return "This page is used to delete startup id"

if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)

