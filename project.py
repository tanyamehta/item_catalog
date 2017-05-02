from flask import Flask, render_template, request, redirect, url_for, \
    flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
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

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase
                    + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
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


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps(
                'Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = \
            make_response(json.dumps(
                "Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps(
                "Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps(
                'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

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
        ' " style = "width: 300px;height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output


@app.route('/gdisconnect')
def gdisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Execute HTTP GET request to revoke current token

    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':

        # Reset the user's session

        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('User disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = \
            make_response(json.dumps('''Failed to revoke token for \
                                     given user! \
                                     result = %s \
                                     credentials = %s'''
                                     % (result, credentials)), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = \
        session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    menuItem = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(MenuItem=menuItem.serialize)


@app.route('/')
@app.route('/restaurants')
def restaurant1():
    restaurant = session.query(Restaurant).all()
    if 'username' not in login_session:
        return render_template('publicrestaurantall.html',
                               restaurant=restaurant)
    else:
        return render_template('restro.html', restaurant=restaurant)


@app.route('/restaurants/new/restro', methods=['GET', 'POST'])
def newRestro():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestro = Restaurant(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newRestro)
        session.commit()
        return redirect(url_for('restaurant1'))
    else:
        return render_template('newrestro.html')

# Create route for editMenuItem function here

@app.route('/restaurant/<int:id>/edit/', methods=['GET', 'POST'])
def editRestro(id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestro = session.query(Restaurant).filter_by(id=id).one()
    if editedRestro.user_id != login_session['user_id']:
        flash('Not authorised to edit this restaurant')
        return redirect(url_for('restaurant1'))
    if request.method == 'POST':
        if request.form['name']:
            editedRestro.name = request.form['name']
        session.add(editedRestro)
        session.commit()
        return redirect(url_for('restaurant1'))
    else:
        return render_template('editrestro.html', item=editedRestro)

# Create a route for deleteMenuItem function here

@app.route('/restaurant/<int:id>/delete/', methods=['GET', 'POST'])
def deleteRestro(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    RestroToDelete = \
        session.query(Restaurant).filter_by(restaurant_id=restaurant_id).one()
    if RestroToDelete.user_id != login_session['user_id']:
        flash('Error:Cant delete')
        return redirect(url_for('restaurant1'))
    if request.method == 'POST':
        query = \
            session.query(MenuItem).filter_by(
                restaurant_id=RestroToDelete.id).all()
        for q in query:
            session.delete(q)
            session.commit()
        session.delete(RestroToDelete)
        session.commit()
        return redirect(url_for('restaurant1'))
    else:
        return render_template('deleterestro.html',
                               restaurant_id=restaurant_id)


@app.route('/')
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    restaurant = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = \
        session.query(MenuItem).filter_by(restaurant_id=restaurant.id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html',
                               restaurant=restaurant, items=items)
    else:
        return render_template('menu.html', restaurant=restaurant,
                               items=items)


#Create route for newMenuItem function here

@app.route('/restaurants/<int:restaurant_id>/new/', methods=['GET',
           'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'],
                           restaurant_id=restaurant_id,
                           user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New menu item created')
        return redirect(url_for('restaurantMenu',
                        restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html',
                               restaurant_id=restaurant_id)


@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/edit/',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if editedItem.user_id != login_session['user_id']:
        return redirect(url_for('restaurant1'))
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item has been edited')
        return redirect(url_for('restaurantMenu',
                        restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html',
                               restaurant_id=restaurant_id,
                               menu_id=menu_id, item=editedItem)


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        return redirect(url_for('restaurant1'))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('restaurantMenu',
                        restaurant_id=restaurant_id))
    else:
        return render_template('deletemenuitem.html',
                               restaurant_id=restaurant_id,
                               menu_id=menu_id, item=itemToDelete)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5003)
