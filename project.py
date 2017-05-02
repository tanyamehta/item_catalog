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
from functools import wraps
import requests
app = Flask(__name__)

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Decorator to check user authorization:
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def showLogin():
    """ Render the login page after a random state token is created.
        
    Creates a random anti-forgery state token with each GET request sent to
    localhost:5000/login before rendering the login page.
    
    Returns:
        The login page.
    """
    state = ''.join(random.choice(string.ascii_uppercase
                    + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# User function helper:
def createUser(login_session):
    """ Creates a new user in the database.
    Args:
        login_session: session object with user data.
    Returns:
        user.id: generated distinct integer value identifying the newly created
            user.
    """
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ Returns the user object associated with the given id number.
    Args:
        user_id: An integer identifying a distinct user.
    Returns:
        A user object containing all fields of the found row in the database.
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ Return a user ID from the database.
    Returns a user id for a given e-mail address if the e-mail address belongs
    to a user stored in the database.
    Args:
        email: e-mail address of a user.
    Returns:
        If successful, the user id to the given e-mail address, otherwise
            nothing.
    """
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
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
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
            make_response(json.dumps('Failed to revoke token for given user!'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    """ Returns all restaurants in JSON format. """
    restaurant = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = \
        session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    """ Returns restaurant menu in JSON format. """

    menuItem = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(MenuItem=menuItem.serialize)


@app.route('/')
@app.route('/restaurants')
def restaurant1():
    """"Shows all restaurant collection in the database"""

    restaurant = session.query(Restaurant).all()
    if 'username' not in login_session:
        return render_template('publicrestaurantall.html',
                               restaurant=restaurant)
    else:
        return render_template('restro.html', restaurant=restaurant)


@app.route('/restaurants/new/restro', methods=['GET', 'POST'])
@login_required # Using the login decorator function
def newRestro():
    """Create new restaurant in the database
        
    Returns:
        on GET: Page to create a new restaurant.
        on POST: Redirect to main page after restaurant has been created.
        Login page when user is not signed in.
    """
    if request.method == 'POST':
        newRestro = Restaurant(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newRestro)
        session.commit()
        return redirect(url_for('restaurant1'))
    else:
        return render_template('newrestro.html')

# Create route for editMenuItem function here

@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
@login_required # Using the login decorator function
def editRestro(restaurant_id):
    """ Edit a restaurant in the database.
        
    Args:
        restaurant_id: An integer identifying a distinct restaurant.
        
    Returns:
        on GET: Page to edit a restaurant.
        on POST: Redirect to main page after restaurant has been edited.
        Login page when user is not signed in.
        Alert when user is trying to edit a restaurant he is not authorized to.
    """
        
    editedRestro = session.query(Restaurant).filter_by(id=restaurant_id).one()
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
        return render_template('editrestro.html', editRestro=editedRestro)

# Create a route for deleteMenuItem function here

@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
@login_required # Using the login decorator function
def deleteRestro(restaurant_id):
    """ delete a restaurant in the database.
        
    Args:
        restaurant_id: An integer identifying a distinct restaurant.
        
    Returns:
        on GET: Page to delete a restaurant.
        on POST: Redirect to main page after restaurant has been deleted.
        Login page when user is not signed in.
        Alert when user is trying to delete a restaurant he is not authorized to.
    """
    
    RestroToDelete = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    if RestroToDelete.user_id != login_session['user_id']:
        flash('Error:Cant delete')
        return redirect(url_for('restaurant1'))
    if request.method == 'POST':
        session.delete(RestroToDelete)
        flash('Successfully deleted Restaurant.')
        session.commit()
        return redirect(url_for('restaurant1'))
    else:
        return render_template('deleterestro.html',
                               restaurant=restaurant_id)


@app.route('/')
@app.route('/restaurants/<int:restaurant_id>/')
def restaurantMenu(restaurant_id):
    """show all menu of a distinct restaurant
    
    Args:
        restaurant_id: An integer identifying a distinct collection.
    """
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
                               items=items, creator=creator)


#Create route for newMenuItem function here

@app.route('/restaurants/<int:restaurant_id>/new/', methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    """ Create a new menu item in the database.
    
    Args:
        restaurant_id: An integer identifying a distinct restaurant.
        
    Returns:
        on GET: Page to create a new menu item.
        on POST: Redirect to collection page after album has been created.
        Login page when user is not signed in.
        Alert when user is trying to create an item he is not authorized to.
    """
    restaurant = \
        session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'],
                           price=request.form['price'],
                           course=request.form['course'],
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


@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/edit/', methods=['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, menu_id):
    """ Edit an existing Menu item in the database.
    
    Args:
        restaurant_id: An integer identifying a distinct restaurant.
        menu_id: An integer identifying a distinct Menu Item.
        
    Returns:
        on GET: Page to edit a menu item.
        on POST: Redirect to Menu page after menu item has been edited.
        Login page when user is not signed in.
        Alert when user is trying to edit a menu item he is not authorized to.
    """
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if editedItem.user_id != login_session['user_id']:
        flash ('You are not authorized to edit this menu item')
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


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, menu_id):
    """ Deletes an existing Menu Item in the database.
    
    Args:
        menu_id:
        restaurant_id: An integer identifying a distinct restaurant.
        
    Returns:
        on GET: Page to delete a menu item.
        on POST: Redirect to Menu page after menu item has been deleted.
        Login page when user is not signed in.
        Alert when user is trying to delete a menu item he is not authorized to.
    """
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        flash('You are not authorized to delete this item')
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
