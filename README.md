# item_catalog
This is a python module that creates a website and JSON API for a list of items grouped into a category. Users can edit or delete items they've creating. Adding items, deleteing items and editing items requiring logging in with Google+ or Facebook.

# Instructions to run Project:

   Set up a Google Plus auth application.

go to https://console.developers.google.com/project and login with Google.
Create a new project
Name the project
Select "API's and Auth-> Credentials-> Create a new OAuth client ID" from the project menu
Select Web Application
On the consent screen, type in a product name and save.
Click create client ID
Click download JSON and save it into the root director of this project.
Rename the JSON file "client_secrets.json"

# Setup The database and starting the server:

In the root director, use the command vagrant up
The vagrant machine will install.
Once it's complete, type vagrant ssh to login to the VM.
In the vm, cd /vagrant
type "pyhon database_setup.py" this will create the database with the categories defined in that script.
type "python project.py" to start the server.
Start using the website by typing http://localhost:5003/ in browser
