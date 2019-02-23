from google.appengine.ext import db

from user import User
import helper

# A model named Post that stores a new post to the db;
# attributes it takes in: the user's id, the subject and content
# of the post, the time it was created, and when it was last modified
class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # Gets a user's username
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    # Renders post's page
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return helper.jinja_render_str("post.html", p=self)
