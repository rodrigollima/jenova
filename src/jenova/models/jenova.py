from ..components.extensions import db
from datetime import datetime
from sqlalchemy.ext.associationproxy import association_proxy

class Reseller(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(25), nullable=False, unique=True)
  company = db.Column(db.String(40))
  email = db.Column(db.String(50))
  phone = db.Column(db.Integer)
  enabled = db.Column(db.Boolean, default=True)

  # Many-To-Many
  services = association_proxy('reseller_in_services', 'service')
  # One-To-One
  user = db.relationship('User', backref='reseller', uselist=False, cascade='all,delete-orphan')
  # One-To-Many
  clients = db.relationship('Client', 
    backref='reseller', cascade='all,delete-orphan', lazy='dynamic')

  created_at = db.Column(db.DateTime, default=datetime.now())

class ResellerServices(db.Model):
  __tablename__ = 'reseller_services'
  reseller_id = db.Column(db.Integer, db.ForeignKey('reseller.id'), primary_key=True)
  service_id = db.Column(db.Integer, db.ForeignKey('service.id'), primary_key=True)

  reseller = db.relationship('Reseller', backref=db.backref('reseller_in_services', cascade='all,delete-orphan'))
  service = db.relationship('Service')

  def __init__(self, service = None, reseller = None):
    self.reseller = reseller
    self.service = service

class Client(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  reseller_id = db.Column(db.Integer, db.ForeignKey('reseller.id'), nullable=False)

  company = db.Column(db.String(40))
  name = db.Column(db.String(25), nullable=False, unique=True)
  email = db.Column(db.String(50))
  phone = db.Column(db.Integer)
  
  # One-To-Many relationships
  user = db.relationship('User', 
    backref='client', cascade='all,delete-orphan', lazy='dynamic')
  domain = db.relationship('Domain', backref='client', cascade='all,delete-orphan', lazy='dynamic')
  
  created_at = db.Column(db.DateTime, default=datetime.now())

  def __repr__(self):
    return '<Client %r>' % self.name

class Features(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(100), nullable=False, unique=True)
  desc = db.Column(db.String(255), nullable=False)
  value = db.Column(db.String(255), nullable=False)

  def __repr__(self):
    return '<Features %r>' % self.name

cos_features_mapping = db.Table('cos_features_mapping',
  db.Column('features_id', db.Integer, db.ForeignKey('features.id')),
  db.Column('cos_id', db.Integer, db.ForeignKey('cos.id'))
)

class Cos(db.Model):
  __tablename__ = 'cos'

  id = db.Column(db.Integer, primary_key=True)
  zimbra_id = db.Column(db.String(255))
  name = db.Column(db.String(100), nullable=False)
  service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
  
  # Many-To-Many
  features = db.relationship('Features', secondary=cos_features_mapping, 
    backref=db.backref('cos', lazy='dynamic'))
  # Many-To-One
  #zcos_quota = db.relationship('DomainZimbraCosQuota', 
  #  backref='cos', cascade='all,delete-orphan', lazy='dynamic')

  def __repr__(self):
    return '<Cos %r>' % self.name

cos_domain_mapping = db.Table('cos_domain_mapping',
  db.Column('cos_id', db.Integer, db.ForeignKey('cos.id')),
  db.Column('domain_id', db.Integer, db.ForeignKey('domain.id'))
)

class Domain(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  zimbra_id = db.Column(db.String(255))
  name = db.Column(db.String(100), nullable=False)
  client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
  
  services = association_proxy('domain_in_services', 'service')

  # Many-To-Many
  cos = db.relationship('Cos', secondary=cos_domain_mapping, backref=db.backref('domain', lazy='dynamic'))
  # One-To-Many relationship
  #zcos_quota = db.relationship('DomainZimbraCosQuota', 
  #  backref='domain', cascade='all,delete-orphan', lazy='dynamic')
  admin_account = db.Column(db.String(255))
  created_at = db.Column(db.DateTime, default=datetime.now())
  last_update = db.Column(db.DateTime)

  def __repr__(self):
    return '<Domain %r>' % self.name

class DomainServiceState(db.Model):
  domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), primary_key=True)
  service_id = db.Column(db.Integer, db.ForeignKey('service.id'), primary_key=True)
  enabled = db.Column(db.Boolean, default=False)
  last_sync = db.Column(db.DateTime)

  domain = db.relationship(Domain, backref=db.backref('domain_in_services', cascade='all,delete-orphan'))
  service = db.relationship('Service')

  def __init__(self, service=None, domain=None, enabled=False):
    self.service = service
    self.domain = domain
    self.enabled = enabled

#domain_service_mapping = db.Table('domain_service_mapping',
#  db.Column('domain_id', db.Integer, db.ForeignKey('domain.id')),
#  db.Column('service_id', db.Integer, db.ForeignKey('service.id'))
#)

class Service(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  # Many-To-Many association
  #domain = db.relationship('Domain', secondary=domain_service_mapping, backref=db.backref('service', lazy='dynamic'))
  cos = db.relationship('Cos', backref='service', cascade='all,delete-orphan', lazy='dynamic')

  name = db.Column(db.String(100), nullable=False, unique=True)
  # Pretty name for the service
  service_desc = db.Column(db.String(100), nullable=False)
  # zimbra / mxhero / dns
  service_type = db.Column(db.String(100), nullable=False)
  service_host = db.Column(db.String(100), nullable=False)
  service_url = db.Column(db.String(100))
  service_api = db.Column(db.String(100))

  # One-To-One
  credentials = db.relationship('ServiceCredentials', 
    backref='service', uselist=False, cascade='all,delete-orphan')
  created_at = db.Column(db.DateTime, default=datetime.now())

  def __repr__(self):
    return '<Service %r>' % self.name

# TODO: use encryption
class ServiceCredentials(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  identity = db.Column(db.String(255))
  secret = db.Column(db.String(255))

  service_id = db.Column(db.Integer, db.ForeignKey('service.id'))

  def __repr__(self):
    return '<ServiceCredentials identity: %r secret: %r>' % (self.identity, self.secret)

class ZimbraDomainReport(db.Model):
  id = db.Column(db.Integer, primary_key=True) 
  service_id = db.Column(db.Integer, db.ForeignKey('service.id'))

  domain = db.Column(db.String(100), nullable=False)
  bemail = db.Column(db.Integer, nullable=False)
  bemail_plus = db.Column(db.Integer, nullable=False)
  standard = db.Column(db.Integer, nullable=False)
  professional = db.Column(db.Integer, nullable=False)
  zcs_version = db.Column(db.String(100), nullable=False)
  report_time = db.Column(db.DateTime, nullable=False)

user_scope_mapping = db.Table('user_scope_mapping',
  db.Column('scope_id', db.Integer, db.ForeignKey('scope.id')),
  db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
  reseller_id = db.Column(db.Integer, db.ForeignKey('reseller.id'))
  
  name = db.Column(db.String(40), nullable=False)
  email = db.Column(db.String(50), nullable=False)
  login = db.Column(db.String(25), nullable=False, unique=True)
  # hash password
  password = db.Column(db.String(255), nullable=False)
  api_enabled = db.Column(db.Boolean, default=False)
  enabled = db.Column(db.Boolean, default=True)
  global_admin = db.Column(db.Boolean, default=False)
  admin = db.Column(db.Boolean, default=False)
  desc = db.Column(db.String(255))
  # One-To-Many
  permissions = db.relationship('Permissions', backref='user', cascade='all,delete-orphan')
  #options = db.relationship('Permissions', backref='user', cascade='all,delete-orphan')
  #options = db.relationship('Options', backref='user', cascade='all,delete-orphan')
  
  created_at = db.Column(db.DateTime, default=datetime.now())

  def __repr__(self):
    return '<User %r>' % self.login

class Scope(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(60), nullable=False, unique=True)
  # One-To-Many
  permissions = db.relationship('Permissions', backref='scope', cascade='all,delete-orphan')
  # Many-To-Many
  user = db.relationship('User', secondary=user_scope_mapping, backref=db.backref('scope', lazy='dynamic'))

class Permissions(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  read = db.Column(db.Boolean, default=False)
  write = db.Column(db.Boolean, default=False)
  delete = db.Column(db.Boolean, default=False)
  edit = db.Column(db.Boolean, default=False)

  scope_id = db.Column(db.Integer, db.ForeignKey('scope.id'), nullable=False)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class DnsRecordBackup(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  domain = db.Column(db.String(100), nullable=False)
  records = db.Column(db.BLOB, nullable=False)
  created_at = db.Column(db.DateTime, default=datetime.now())

class Notices(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  author = db.Column(db.String(100), nullable=False)
  created_at = db.Column(db.DateTime, default=datetime.now())
  started_at = db.Column(db.DateTime)
  ended_at = db.Column(db.DateTime)
  notice_type = db.Column(db.String(100), nullable=False)
  service_name = db.Column(db.String(100), nullable=False)
  description = db.Column(db.String(2048), nullable=False)
  sla_impact = db.Column(db.Float(), default=0, nullable=False)

