from jenova.models import User, UserSchema
from jenova.components import Security, create_app
from datetime import datetime
import sys, jwt, uuid

def create_user(username, password):
  db = create_app(local=True)
  user = User(
    login = username,
    name = username,
    email = 'operacao@inova.net',
    password = Security.hash_password(password),
    api_enabled = True,
    global_admin = True
  )

  db.add(user)
  db.commit()

  user = db.query(User).filter_by(login = username).first()
  token = jwt.encode({'user' : UserSchema().dump(user).data}, str(uuid.uuid4()), algorithm='HS256')
  print token

if __name__ == '__main__':
  username, passwd = sys.argv[1:]
  create_user(username, passwd)