from marshmallow import Schema, fields

class ResellerNameSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  company = fields.String()
  enabled = fields.Boolean()

class ClientNameSchema(Schema):
  name = fields.String()
  company = fields.String()
  phone = fields.String()
  email = fields.String()
  reseller = fields.Nested(ResellerNameSchema)

class PermissionsScopeSchema(Schema):
  id = fields.Integer()
  read = fields.Boolean()
  write = fields.Boolean()
  delete = fields.Boolean()
  edit = fields.Boolean()

class UserScopeSchema(Schema):
  login = fields.String()
  client = fields.Nested(ClientNameSchema, only=('name'))
  reseller = fields.Nested(ResellerNameSchema, only=('name'))
  permissions = fields.Nested(PermissionsScopeSchema, many=True)

class ScopeSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  users = fields.Nested(UserScopeSchema, many=True)

class PermissionsSchema(Schema):
  id = fields.Integer()
  read = fields.Boolean()
  write = fields.Boolean()
  delete = fields.Boolean()
  edit = fields.Boolean()
  scope = fields.Nested(ScopeSchema)
  
class ScopeOptionsSchema(Schema):
  id = fields.Integer()
  scope = fields.String()
  users = fields.Nested(UserScopeSchema, many=True)

class UserSchema(Schema):
  id = fields.Integer()
  client_id = fields.Integer()
  login = fields.String()
  name = fields.String()
  email = fields.String()
  api_enabled = fields.Boolean()
  enabled = fields.Boolean()
  admin = fields.Boolean()
  global_admin = fields.Boolean()
  permissions = fields.Nested(PermissionsSchema, many=True)
  scope_options = fields.Nested(ScopeOptionsSchema, many=True)
  
  client = fields.Nested(ClientNameSchema)
  reseller = fields.Nested(ResellerNameSchema)
  created_at = fields.DateTime()

class ClientSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  company = fields.String()
  phone = fields.String()
  email = fields.String()
  users = fields.Nested(UserSchema, many=True)
  reseller = fields.Nested(ResellerNameSchema, only=('name')) 
  created_at = fields.DateTime()

class ServiceSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  service_name = fields.String()
  service_desc = fields.String()
  service_type = fields.String()
  service_host = fields.String()
  service_url = fields.String()
  service_api = fields.String()
  created_at = fields.DateTime()

class ResellerSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  enabled = fields.Boolean()
  email = fields.String()
  phone = fields.String()
  company = fields.String()
  users = fields.Nested(UserSchema, many=True)
  clients = fields.Nested(ClientSchema, many=True)
  created_at = fields.DateTime()
  services = fields.Nested(ServiceSchema, many=True)  
  

class DomainSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  admin_account = fields.String()
  client = fields.Nested(ClientSchema, only=('name'))
  services = fields.Nested(ServiceSchema, many=True)
  created_at = fields.DateTime()

class DomainServiceStateSchema(Schema):
  enabled = fields.Boolean()
  last_sync = fields.DateTime()
  service = fields.Nested(ServiceSchema, only=('name', 'service_desc', 'service_type'))

class ZimbraDomainReportSchema(Schema):
  id = fields.Integer()
  service = fields.Nested(ServiceSchema, only=('name'))
  domain = fields.String(required=True)
  bemail = fields.Integer(required=True)
  bemail_plus = fields.Integer(required=True)
  standard = fields.Integer(required=True)
  professional = fields.Integer(required=True)
  zcs_version = fields.String()
  report_time = fields.DateTime()

class FeaturesSchema(Schema):
  id = fields.Integer()
  name = fields.String()
  desc = fields.String()

class SyncStateSchema(Schema):
  id = fields.Integer()
  status = fields.String()
  last_message = fields.String()
  last_sync = fields.DateTime()
  created_at = fields.DateTime()

class CosSchema(Schema):
  id = fields.Integer()
  cos_external_id = fields.String()
  name = fields.String()
  syncstate = fields.Nested(SyncStateSchema)
  features = fields.Nested(FeaturesSchema, many=True)

class DnsRecordsSchema(Schema):
  content = fields.String()
  type = fields.String()
  name = fields.String()
  ttl = fields.Integer()

class DnsSoaSchema(Schema):
  kind = fields.String()
  name = fields.String()
  url = fields.String()
  last_check = fields.Integer()
  records = fields.Nested(DnsRecordsSchema, many=True)

class DnsRecordBackupSchema(Schema):
  id = fields.Integer()
  domain = fields.String()
  records = fields.String()
  created_at = fields.DateTime()


class NoticesSchema(Schema):
  id = fields.Integer()
  author = fields.String()
  created_at = fields.DateTime()
  started_at = fields.DateTime()
  ended_at = fields.DateTime()
  notice_type = fields.String()
  service_name = fields.String()
  description = fields.String()
  sla_impact = fields.Float()
