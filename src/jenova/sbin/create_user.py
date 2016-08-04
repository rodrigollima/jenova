from jenova.models import User, UserSchema
from jenova.components import Security
from datetime import datetimet
from jenova.components import create_app
import sys, jwt

def create_user(username, password):
  db = create_app(local=True)
  db.query(Domain).all()
  user = User(
    login = username,
    name = username,
    email = 'operacao@inova.net',
    password = Security.hash_password(password),
    api_enabled = True,
    global_admin = True
  )

  db.session.add(user)
  db.session.commit()

  user = db.session.query(User).filter_by(login = username).first()
  token = jwt.encode({'user' : UserSchema().dump(user).data}, SKEY, algorithm='HS256')
  print token

if __name__ == '__main__':
  username, passwd = sys.argv[1:]
  create_user(username, passwd)
