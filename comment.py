from google.appengine.ext import db

from user import User

# A class named Comment that stores a comment to a post;
# attributes it takes in: the user's id, the post's id,
# the comment itself, the time it was created and the last time it was modified
class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # Gets a user's username
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

