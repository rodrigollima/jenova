import uuid, hashlib, os, yaml, logging.config, json, requests, re
from bcrypt import hashpw, gensalt
from collections import namedtuple
from sqlalchemy import create_engine
from datetime import datetime

CONFIG_FILE = os.environ.get('CONFIG_PATH_FILE')

ZimbraGrant = namedtuple(
  'ZimbraGrant', [ 
    'target_name', 
    'target_type', 
    'grantee_name',
    'grantee_type', 
    'right', 
    'deny'
  ]
)

class CallLogger(object):
  @classmethod
  def logger(cls):
    with open(CONFIG_FILE) as f:
      _, _, logger_config = yaml.load_all(f)
    
    logging.config.dictConfig(logger_config['logger'])
    return logging.getLogger(os.environ.get('HOSTNAME'))

logger = CallLogger.logger()

class Config(object):
  @classmethod
  def load(cls):
    with open(CONFIG_FILE) as f:
      main_config, global_zimbra_config, logger_config = yaml.load_all(f)
      return main_config, global_zimbra_config, logger_config

  @classmethod
  def gen_zimbra_grants(cls, zgrants, target_name, target_dlist, grantee_type='grp'):
    """
    :param grantee_type: usr|grp|egp|all|dom|edom|gst|key|pub|email
    """
    result_grants = []
    for zgrant in zgrants:
      result_grants.append(
        ZimbraGrant(
          target_name = target_name,
          target_type = 'domain',
          grantee_name = target_dlist,
          grantee_type = grantee_type,
          right = zgrant,
          deny = 0
        )
      )

    return result_grants


class InvalidCredentials(Exception):
  status_code = 400
  def __init__(self, message, status_code=None):
    Exception.__init__(self)
    self.msg = message
    self.status_code = status_code

class Security(object):
  def __init__(self, auth, authtoken, apikey, secretkey):
    self.auth = auth
    self.authtoken = authtoken
    self.apikey = apikey
    self.secretkey = secretkey
    
  def is_valid_credentials(self):
    if self.authtoken and self.is_valid_token():
      return True
    elif self.apikey and self.secretkey:
      if not self.is_valid_secret_key():
        raise InvalidCredentials('Wrong credentials!', 401)
    else:
      return False

  def is_valid_token(self):
    return False

  def is_valid_secret_key(self):
    return self.check_password(self.auth.secret_key, self.secretkey)
  
  @classmethod
  def gen_secret_key(cls, password):
    plain_secretkey = hashpw(password, gensalt(log_rounds=13)).split('13$')[1]
    hashed_secretkey = hashpw(plain_secretkey, gensalt(log_rounds=13))
    return plain_secretkey, hashed_secretkey
    
  @classmethod
  def hash_password(cls, password):
    return hashpw(password, gensalt(log_rounds=13))

  @classmethod
  def check_password(cls, hashed_password, user_password):
    return hashpw(user_password, hashed_password) == hashed_password

  @classmethod
  def get_jwt_skey(self):
    if os.environ.get('NODE_ENV') == 'development':
      return 'changeme'
    return os.environ.get('JWT_SECRET_KEY')