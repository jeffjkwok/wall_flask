from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'the_wall')
app.secret_key = 'password'
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def loginPage():
	if 'reg' not in session:
		session['reg'] = True
	return render_template('login.html')

@app.route('/', methods=['POST'])
def flipForm():
	if session['reg'] == True:
		session['reg'] = False
	else:
		session['reg'] = True
	return redirect('/')

@app.route('/process', methods=['POST'])
def login_reg():
	validations = 0
	if request.form.get('login') is not None:
		if len(request.form['email'])<1 or not EMAIL_REGEX.match(request.form['email']):
			validations +=1
			flash('Email cannot be blank or is invalid')
		if len(request.form['password'])<1:
			validations +=1
			flash('Password was empty')
		if validations == 0 :
			query = 'SELECT password, username, id FROM users WHERE email = "{}"'.format(request.form['email'])
			user = mysql.query_db(query)
			if user and bcrypt.check_password_hash(user[0]['password'], request.form['password']):
				session['username'] = user[0]['username']
				session['id'] = user[0]['id']
				return redirect('/dashboard')
			else:
				flash('There is no account associated with this email')
		return redirect('/')

	elif request.form.get('register') is not None:
		# Validations
		if len(request.form['username'])<4:
			validations += 1
			flash('Username needs to be longer than 4 characters')
		if len(request.form['email'])<1 or not EMAIL_REGEX.match(request.form['email']):
			validations +=1
			flash('Email cannot be blank or is invalid')
		query = 'SELECT username FROM users WHERE email = "{}"'.format(request.form['email'])
		user = mysql.query_db(query)
		print user
		if len(user) > 0:
			validations +=1
			flash('Email already in use!')
		if len(request.form['password'])<4 or request.form['password'] != request.form['c_password']:
			validations +=1
			flash('Password cannot be blank or does not match')
		if validations == 0 :
			password = bcrypt.generate_password_hash(request.form['password'])
			query = 'INSERT INTO users (username, email, password, created_at, updated_at) VALUES (:username, :email, :password, NOW(), NOW())'
			data = {
				'username': request.form['username'],
				'email': request.form['email'],
				'password': password
			}
			mysql.query_db(query, data)
			# For Session
			query = "SELECT id, username FROM users WHERE email ='{}'".format(request.form['email'])
			user = mysql.query_db(query)
			session['username'] = user[0]['username']
			session['id'] = user[0]['id']
			return redirect('/dashboard')
		elif validations >= 1:
			return redirect('/')
	return redirect('/')

@app.route('/dashboard')
def dashboard():
	if session.get('username') is None:
		return redirect('/')
	query = "SELECT posts.id, posts.content, posts.created_at, users.username FROM posts LEFT JOIN users ON posts.user_id=users.id"
	messages = mysql.query_db(query)
	query = "SELECT comments.content, comments.created_at, users.username, posts.id AS message_id FROM comments LEFT JOIN users ON comments.user_id=users.id LEFT JOIN posts ON comments.post_id=posts.id"
	comments = mysql.query_db(query)
	# print comments

	return render_template('index.html', messages=messages, comments=comments)

@app.route('/logout')
def logout():
	session.clear()
	return redirect('/')

@app.route('/post', methods=['POST'])
def post():
	if request.form.get('message') is not None:
		query = 'INSERT INTO posts (content, user_id, created_at, updated_at) VALUES (:content, :user_id, NOW(), NOW())'
		data = {
			'content': request.form['content'],
			'user_id': session['id']
		}
		mysql.query_db(query, data)
		return redirect('/dashboard')
	elif request.form.get('comment') is not None:
		query = "INSERT INTO comments (content, user_id, post_id, created_at, updated_at) VALUES (:content, :user_id, :post_id, NOW(), NOW())"
		data = {
			'content': request.form['content'],
			'user_id': session['id'],
			'post_id': request.form['message_id']
		}
		mysql.query_db(query, data)
		return redirect('/dashboard')

app.run(debug=True)
