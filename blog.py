# Import all libraries/models
import re
import hmac
import webapp2
from google.appengine.ext import db
from user import User
from post import Post
from comment import Comment
from like import Like
import helper

# Set the secret to a random phrase
secret = 'secretPassword'

# Using secret make a secure value
def secureValue(value):
    return '%s|%s' % (value, hmac.new(secret, value).hexdigest())

# Check to make sure the secure value is secret
def check_if_secure(secure_val):
    value = secure_val.split('|')[0]
    if secure_val == secureValue(value):
        return value

# A class that stores helper methods
class BlogHandler(webapp2.RequestHandler):

    # A method that writes output to a client's browser
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # A method that renders HTML using templates
    def render_str(self, template, **params):
        params['user'] = self.user
        return helper.jinja_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # A method that gives the browser the secure cookie from set
    def setCookie(self, name, value):
        cookieValue = secureValue(value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookieValue))

    # A method that reads the cookie to the browser
    def readCookie(self, name):
        cookieValue = self.request.cookies.get(name)
        return cookieValue and check_if_secure(cookieValue)

    # A method that verifies if the user exists
    def login(self, user):
        self.setCookie('user_id', str(user.key().id()))

    # A method that resets the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # A method whcih runs for each page to check the user's login status
    # using the cookie
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.readCookie('user_id')
        self.user = uid and User.by_id(int(uid))

# Get the blog's key
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Home page with all posts sorted from newest to oldest
class BlogFront(BlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id)

# An individual post's page
class PostPage(BlogHandler):

    # Renders the page with the post, comments, and likes
    def get(self, post_id):
        k = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(k)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("permalink.html", post=post, likeCount=likes.count(),
                    comments=comments, error=error)

    # Add a like or a comment
    def post(self, post_id):
        k = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(k)

        if not post:
            self.error(404)
            return

        c = ""
        if(self.user):
            # Add a like to a post
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))
                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You can't like your " +
                                  "own post!")
                    return
                # Else add the like
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()

            # Adds comment and creates new tuple
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=You can't edit, like, or comment" +
                          " a post without signing in!")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post,
                    comments=comments, likeCount=likes.count(),
                    new=c)

# Add a new post
class NewPost(BlogHandler):

    # Renders new post page
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    # Creates the post and then redirects to it
    def post(self):

        # Authorizing
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=blog_key(), user_id=self.user.key().id(),
                        subject=subject, content=content)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Please add a subject and content."
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

# Delete a post
class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            k = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(k)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/?deleted_post_id="+post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this post!")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!")

# Edit a post
class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            k = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(k)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this post!")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!")

    def post(self, post_id):
        if self.user:
            k = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(k)
            if post.user_id == self.user.key().id():
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    k = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    post = db.get(k)
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "subject and content, please!"
                    self.render("editpost.html", subject=subject,
                                content=content, error=error)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this post!")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!")

# Delete a comment
class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            k = db.Key.from_path('Comment', int(comment_id),
                                 parent=blog_key())
            c = db.get(k)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to " +
                          "delete your comment!!")

# Edit a comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            k = db.Key.from_path('Comment', int(comment_id),
                                 parent=blog_key())
            c = db.get(k)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, post_id, comment_id):
        # Make sure there is a user
        if self.user:
            # Make sure this was the user who wrote the comment
            k = db.Key.from_path('Comment', int(comment_id),
                parent=blog_key())
            c = db.get(k)
            if c.user_id == self.user.key().id():
                # Make sure they have included a subject and content
                comment = self.request.get('comment')
                if comment:
                    c.comment = comment
                    c.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "Please add a subject and content!"
                    self.render("editpost.html", subject=subject,
                                content=content, error=error)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " save an edit to your post!!")

# Validation Paramaters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Signup Form
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Register a user
class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

# Login a user
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html', error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

# Logout a user
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

# Routes
app = webapp2.WSGIApplication([
                               ('/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)

