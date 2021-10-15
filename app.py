#!/usr/bin/env python3
# Change Active Directory Password via Web+LDAP
# (C) 2021 Nabla2 s.r.l., Michael Papotto & Giovanni Faglioni
#

from subprocess import Popen, PIPE, run
from flask import Flask, render_template, request, url_for, flash, redirect
from flask_wtf.csrf import CSRFProtect, CSRFError

# Necessary because Form by wtforms causes problems with csrf
from flask_wtf import FlaskForm 
from wtforms import StringField, validators

from ldap3 import Server, Connection, SAFE_SYNC, ALL, core
import json
import sys
import secrets
import string

# Globals
# if len(sys.argv) != 2:
#	print("I need a config file.")
#	exit(1)
# else:
#	customer = sys.argv[1]
conf_filename = "webadpw.conf"
customer_css_file = "css/webadpw.css"
errors = {
	"complexity":"La nuova password non rispetta i criteri di complessita' di sistema. Contatta l'amministratore per maggiori dettagli.",
	"longer":"La nuova password e' troppo corta. Contatta l'amministratore per maggiori dettagli."
}

# Read customer configuration
def read_config(conf_filename):
	with open(conf_filename, "r") as f:
		config = json.load(f)
	return config

# Connection to the server
def ldap3_connect(server, base_dn, user_attribute, user_tree, username, password):
	user = "{}={},{},{}".format(user_attribute, username, user_tree, base_dn)
	# print("USER={}".format(user))
	s = Server(server, port=389, get_info=ALL)
	c = Connection(s, user=user, password=password, check_names=True, lazy=False, client_strategy=SAFE_SYNC, raise_exceptions=True)
	c.open()
	return c

# Binding with invalid credential exception management
def ldap3_bind(connection):
	try:
		# print(connection.bind())
		connection.bind()
		return 1
	except core.exceptions.LDAPInvalidCredentialsResult as e:
		for i in str(e).split(','):
			if "data" in i:
				error_code = i
				break

		error_code = error_code.split()[1]
		if (error_code == "52e"):
			# Password not valid
			return 0
		elif (error_code == "532"):
			# Expired but valid password 
			return 2
		elif (error_code == ""):
			# Valid password but not expired
			# This branch is for defencing programming
			return 1
		else:
			# Internal Error
			return -1

# Change password to Active Directory
def ldap3_chpw(connection, base_dn, user_attribute, user_tree, username, password, newpassword):
	dn = "{}={},{},{}".format(user_attribute, username, user_tree, base_dn)
	try:
		connection.extend.microsoft.modify_password(dn, newpassword, password)
		message = "La password di " + username + " ora e' " + newpassword 
		return message
	except core.exceptions.LDAPOperationResult as e:
		error = str(e)#.split('-')[5]
		for i in errors.keys():
			if i in error:
				error = errors[i]
				break
		# flash("AD errors: {}".format(error))
		flash("Errori Active Directory: {}".format(error))
		return "" 

# My Form
class myForm(FlaskForm):
	
	# Check if the new password is equal to the old one. In this case there's an error
	def validate_newpassword(form, field):
		if form.password.data == form.newpassword.data:
			form.newpassword.errors.append('La nuova password deve essere diversa dalla vecchia!')

	username = StringField(u'Username', validators=[validators.input_required()])
	password = StringField(u'Password corrente', validators=[validators.input_required()])
	newpassword = StringField(u'Nuova password', validators=[validators.input_required()])

# Create a Flask Object
app = Flask(__name__)
# Read configuration
config = read_config(conf_filename)
app.config['SECRET_KEY'] = config['secret']
# app.config['WTF_CSRF_SECRET_KEY'] = config['secret']
app.config.update(
	SESSION_COOKIE_SECURE=True, #FIXME: Temporany False because http site. MUST BE changed
	SESSION_COOKIE_HTTPONLY=True, # Client-side JavaScript will not be able to access the session cookie
	SESSION_COOKIE_SAMESITE='Strict', # Prevents the cookie from being sent by the browser to the target site in all cross-site browsing context, even when following a regular link.	
)

# Prevent Cross-Site Request Forgery attack
csrf = CSRFProtect()
csrf.init_app(app)
# print(csrf)

# Route / both in GET and POST method
@app.route('/', methods=['GET', 'POST'])
def index():
	form = myForm(request.form)
	
	if request.method == 'POST':
		# print("CSRF POST: {}".format(form.csrf_token))
		username = form.username.data
		password = form.password.data
		newpassword = form.newpassword.data
		if form.validate():
			# print("CSRF VALIDATE: {}".format(form.csrf_token))
			# print("U: {}, P: {}, NP: {}".format(username,password,newpassword))
			connection = ldap3_connect(config['server'], config['base_dn'], config['user_attribute'], config['user_tree'], username, password)
			code = ldap3_bind(connection)
			connection.unbind()
	
			# print("Code: {}".format(code))
			if code <= 0:
				# print("Password non valida!", flush=True)
				flash("Password corrente errata!")
			else:
				# print("Password valida!", flush=True)
	
				connection = ldap3_connect(config['server'], config['base_dn'], config['user_attribute'], config['user_tree'], config['ldap_manager'], config['ldap_password'])
				code = ldap3_bind(connection)
				message = ldap3_chpw(connection, config['base_dn'], config['user_attribute'], config['user_tree'], username, password, newpassword)
				connection.unbind()

				if message != "":
					return render_template('ok.html', message=message)
		else:
			# print("CSRF ERRORS: {}".format(form.csrf_token))
			print(form.errors)
	else:
		# print("CSRF GET: {}".format(form.csrf_token))
		form.username.data = ''
		form.password.data = ''
		form.newpassword.data = generate_password()
	# print(form.newpassword.errors, flush=True)
	# return render_template('index.html', username=username, password=password, newpassword=newpassword, message=form, form=form)
	return render_template('index.html', customer=customer_css_file, form=form)

def generate_password():
	return ''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits + '@' + '+' + '!' + '-' + '$' ) for _ in range(8))

@app.errorhandler(CSRFError)
def csrf_error(reason):
	return render_template('ok.html', message=reason)

if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=config['http_port'])

