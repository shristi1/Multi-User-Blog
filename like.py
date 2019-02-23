from google.appengine.ext import db


from user import User

# A model named Like that stores a like to a post's likes;
# attributes it takes in: the user's id, and the post's id
class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    # Gets a user's username
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name
