import os
import re
from string import letters
import jinja2
import webapp2
import hashlib
import hmac
import json
from urllib2 import URLError
from datetime import datetime, timedelta
from google.appengine.api import memcache
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class Post(db.Model):
	content = db.TextProperty()
	url = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	creator = db.StringProperty()


class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

SECRET = 'howaboutno'

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s,hash_str(s))

def check_secure_val(h):
	if h:
		val = h.split('|')[0]
		if h == make_secure_val(val):
			return val

class Signup(Handler):

	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username = username,
					  email = email)

		users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")

		for u in users:
			if u.username == username and u.password == password:
				params['error_username'] = "That user is already registered."
				have_error = True
				break

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password):
			params['error_password'] = "That's not a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			u = User(username=username,password=password,email=email)
			u.put()
			secured_cookie = make_secure_val(str(u.key().id()))
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secured_cookie)
			self.redirect('/')

class Login(Handler):
	def render_front(self, username="", error_login=""):
		self.render("login-form.html",username=username, error_login=error_login)

	def get(self):
		self.render("login-form.html")

	def post(self):
		users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")
		msg = 'Invalid Login'
		have_error = True
		username = self.request.get('username')
		password = self.request.get('password')
		for u in users:
			if u.username==username and u.password==password:
				have_error = False
				msg=''
				secured_cookie = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % secured_cookie)
				break

		if have_error:
			self.render_front(username = username, error_login = msg)
		else:
			self.redirect('/')

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect('/login')


class EditPage(Handler):
	def get(self, url):
		cookie_str = self.request.cookies.get('user_id')
		useridprcd = check_secure_val(cookie_str)
		ruser = User.get_by_id(int(useridprcd))

		if useridprcd:
			posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
			content = ""
			for p in posts:
				if p.url==url:
					content = p.content
					break
			self.render("editpost.html",content=content, url=url, username = ruser.username)
		else:
			self.redirect('/login')

	def post(self, url):
		content = self.request.get("content")
		p = Post(content = content, url = url)
		p.put()
		#self.redirect('http://localhost:20080%s' %str(url)) 
		self.redirect('http://daiictwiki.appspot.com%s' %str(url)) #The Switch

class WikiPage(Handler):
	def get(self, url):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		content = ""
		cookie_str = self.request.cookies.get('user_id')
		useridprcd = check_secure_val(cookie_str)
		if useridprcd:
			ruser = User.get_by_id(int(useridprcd))
		else:
			ruser = None
		found = False
		for p in posts:
			if p.url==url:
				content = p.content
				created = p.created
				creator = p.creator
				found = True
				break

		if found:
			self.render("post.html",content=content,created=created, url=url, user=ruser)
		else:
			self.redirect('/_edit%s' %str(url))
		#self.write(url)
		
class AllUsers(Handler):
	def get(self):
		users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")
		self.render("allusers.html", users=users)



PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([
	('/signup', Signup),
	('/login', Login),
	('/logout', Logout),
	('/allusers', AllUsers),
	('/_edit' + PAGE_RE, EditPage),
	(PAGE_RE, WikiPage)
], debug=True)
