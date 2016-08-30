from redis import StrictRedis
from celery.utils.log import get_task_logger
from celery import Task, states
from celery.exceptions import Ignore
from factory import create_celery_app
from datetime import datetime
from sqlalchemy.orm.exc import NoResultFound

from .extensions import db
from .exceptions import TaskZimbraInconsistencyError, TaskError
from .zimbra import ZimbraRequest, ZimbraRequestError, ZimbraReport
from ..models import Cos, Domain, DomainServiceState
from .common import CallLogger, Config
import pickle

celery = create_celery_app()
#logger = get_task_logger(__name__)
logger = CallLogger.logger()

# TODO: Test without global admin accounts!

# 5 minutes
RETRY_TIME = 60 * 5

@celery.task(bind=True)
def create_cos_zimbra_task(self, target_cos, zimbra_config, features, cos_id):
  """Create a new COS in Zimbra. If it already exists, verify if the features match and then update the database
  :param target_cos: The name of the COS
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param features: A dict containing the features for the given COS. feature -> value
  :param cos_id: The jenova db Cos.id
  """
  
  zr = ZimbraRequest(
    admin_url = zimbra_config['service_api'], 
    admin_user = zimbra_config['admin_user'], 
    admin_pass = zimbra_config['admin_password']
  )
  try:
    response = zr.getCos(
      cos_name = str(target_cos), 
    )
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.NO_SUCH_COS':
      logger.info('COS %s does not exist. Creating it...' % target_cos)
      response = zr.createCos(cos_name = target_cos, features = features)
      logger.info('Request success')
      logger.debug(response)
  else:
    for f in response['GetCosResponse']['cos']['a']:
      fkey, fvalue = f['n'], f['_content']
      if fkey in features and not features[fkey] == fvalue:
        self.retry(
          exc = TaskZimbraInconsistencyError('COS %s already exists! Fix feature: %s - Found: %s. MUST be: %s' \
          % (target_cos, fkey, fvalue, features[fkey])),
          countdown = RETRY_TIME
        )

    logger.info('Consistent check passed for cos %s' % target_cos)
  
  response = response.get('CreateCosResponse') or response.get('GetCosResponse')
  zimbra_cos_id = response['cos']['id']
  #for data in response['cos']['a']:
  #  key, value = data['n'], data['_content']
  #  if key == 'zimbraId':
  #    zimbra_cos_id = value

  if celery.app.app_context():
    logger.info('Updating database...')
    cos = Cos.query.filter_by(id = cos_id).first()
    cos.zimbra_id = zimbra_cos_id
    db.session.commit()
  else:
    raise TaskError('Could not find app context')

  logger.info('COS %s task processed successfully' % target_cos)

@celery.task(bind=True)
def modify_cos_zimbra_task(self, target_cos, zimbra_config, features, sync_state_id):
  """Update COS attributes in Zimbra. If does not exists, retry after specific time
  :param target_cos: The name of the COS
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param features: A dict containing the features for the given COS. feature -> value
  :param sync_state_id: The jenova db SyncState.id
  """
  zr = ZimbraRequest(
    admin_url = zimbra_config['service_api'], 
    admin_user = zimbra_config['admin_user'], 
    admin_pass = zimbra_config['admin_password']
  )
  zimbra_cos_id = None
  try:
    response = zr.getCos(
      cos_name = str(target_cos), 
    )

    zimbra_cos_id = response['GetCosResponse']['cos']['id']
    #for data in response['GetCosResponse']['cos']['a']:
    #  key, value = data['n'], data['_content']
    #  if key == 'zimbraId':
    #    zimbra_cos_id = value
    #if not zimbra_cos_id:
    #  raise TaskError('Could not find zimbraId. COS: %s' % target_cos)
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.NO_SUCH_COS':
      self.retry(
        exc = TaskError('COS %s does not exist. Retrying after %s minutes...' % (target_cos, RETRY_TIME)),
        countdown = RETRY_TIME
      )
  
  zr.modifyCos(
    zimbra_cos_id = zimbra_cos_id,
    features = features
  )

  if celery.app.app_context():
    logger.info('Updating database...')
    db.session.commit()
  else:
    raise TaskError('Could not find app context')

  logger.info('COS %s task processed successfully' % target_cos)

@celery.task(bind=True)
def delete_cos_zimbra_task(self, target_cos, zimbra_config, cos_id):
  """Update COS attributes in Zimbra. If does not exists, retry after specific time
  :param target_cos: The name of the COS
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param cos_id: The jenova db Cos.id
  """
  zr = ZimbraRequest(
    admin_url = zimbra_config['service_api'], 
    admin_user = zimbra_config['admin_user'], 
    admin_pass = zimbra_config['admin_password']
  )
  zimbra_cos_id = None
  try:
    response = zr.getCos(cos_name = target_cos)
    zimbra_cos_id = response['GetCosResponse']['cos']['id']
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.NO_SUCH_COS':
      # COS does not exists, update database
      if celery.app.app_context():
        logger.info('Updating database...')
        cos = Cos.query.filter_by(id = cos_id).first()
        if cos:
          db.session.delete(cos)
          db.session.commit()
      else:
        raise TaskError('Could not find app context')
  else:
    zr.deleteCos(
      zimbra_cos_id = zimbra_cos_id
    )

    if celery.app.app_context():
      logger.info('Updating database...')
      cos = Cos.query.filter_by(id = cos_id).first()
      if cos:
        db.session.delete(cos)
        db.session.commit()
    else:
      raise TaskError('Could not find app context')

  logger.info('COS %s task processed successfully' % target_cos)

# TODO: Fix syncstate
# TODO: Create admin DL for domain
# TODO: Set an account to administrate the domain
# TODO: Chain tasks
# TODO: Set a default COS for the domain (basic). Creating a new account, it will prepend to the proper COS
@celery.task(bind=True)
def create_domain_zimbra_task(self, zimbra_config, domain_name, domain_id, quota=None):
  """ Create a new domain into Zimbra
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param domain_name: Name of the domain
  :param domain_id: Jenova domain.id 
  :param quota: List containing the COS ID with the max accounts: { 'zimbraId-of-a-cos' : quota, ... }
  """
  is_new_domain, zimbra_domain_id = None, False
  try:
    logger.info('Starting task create_domain_zimbra_task...')
    zr = ZimbraRequest(
      admin_url = zimbra_config['service_api'], 
      admin_user = zimbra_config['admin_user'], 
      admin_pass = zimbra_config['admin_password']
    )
    response = zr.getDomain(domain_name, ['zimbraId', 'zimbraDomainCOSMaxAccounts'])
    zimbra_domain_id = response['GetDomainResponse']['domain']['id']
    logger.info('Domain %s exists. zimbraID: %s' % (domain_name, zimbra_domain_id))
    # Domain exists, must append quota size into domain if exists
    if quota:
      logger.info('Quota exists, formating request...')
      # Prepare for request: [ ('zimbraDomainCOSMaxAccounts', 'zimbra_cos_id:quota_size'), ...] 
      request_quota = []
      for zimbra_cos_id, qsize in quota.items():
        content = ':'.join((zimbra_cos_id, str(qsize)))
        request_quota.append(('zimbraDomainCOSMaxAccounts', content))

      response = zr.modifyDomain(zimbra_domain_id, request_quota)
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.NO_SUCH_DOMAIN':
      is_new_domain = True
      
      # Prepare for request: [ ('zimbraDomainCOSMaxAccounts', 'zimbra_cos_id:quota_size'), ...] 
      request_quota = []
      if quota:
        for zimbra_cos_id, qsize in quota.items():
          content = ':'.join((zimbra_cos_id, str(qsize)))
          request_quota.append(('zimbraDomainCOSMaxAccounts', content))

      response = zr.createDomain(domain_name, attrs = request_quota)
      zimbra_domain_id = response['CreateDomainResponse']['domain']['id']
    else:
      logger.exception(e)
      self.retry(
        exc = TaskError('Unknown error: %s. Retrying after %s minutes...' % (e, RETRY_TIME)),
        countdown = RETRY_TIME
      )

  if celery.app.app_context():
    logger.info('Updating database...')
    domain = Domain.query.filter_by(id = domain_id).first()
    domain.zimbra_id = zimbra_domain_id
    db.session.commit()
  else:
    raise TaskError('Could not find app context')

  return is_new_domain

@celery.task(bind=True)
def create_delegated_zimbra_admin_task(self, is_new_domain, zimbra_config, domain_name, service_id, 
  domain_id, gconf, zgrants, delegated_admin_account = None):
  """ Create a delegated account for administrating the domain. It will create the account and the 
  distribution list with the proper permissions
  :param is_new_domain: Boolean indicating if it's a new domain
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param domain_name: Name of the domain
  :param service_id: Jenova service.id
  :param domain_id: Jenova domain.id 
  :param gconf: global config attributes. Check config.yaml
  :param zgrants: List containing ZimbraGrant objects
  :param delegated_admin_account: Delegated admin account for acting on behalf of the target domain
  """
  logger.info('Starting task create_delegated_zimbra_admin_task...')
  dlist_zimbra_id = None
  dlist_name = '@'.join((gconf['dlist']['admin_list_name'], domain_name))
  zdelegated_admin_account = '@'.join((gconf['admin']['default_name'], domain_name))
  try:
    zr = ZimbraRequest(
      admin_url = zimbra_config['service_api'], 
      admin_user = zimbra_config['admin_user'], 
      admin_pass = zimbra_config['admin_password']
    )
    response = zr.createDistributionList(dlist_name, gconf['dlist']['attrs'].items())
    dlist_zimbra_id = response['CreateDistributionListResponse']['dl']['id']
    if not dlist_zimbra_id:
      raise ValueError('dlist_zimbra_id must not be empty. Must not get here!')
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.DISTRIBUTION_LIST_EXISTS':
      logger.info('DL %s already exists' % dlist_name)
    else:
      logger.exception(e)
      self.retry(
        exc = TaskError('Unknown error: %s. Retrying after %s minutes...' % (e, RETRY_TIME)),
        countdown = RETRY_TIME
      )

  try:
    # SET GRANTS / IDEMPOTENT
    for zgrant in zgrants:
      #logger.info('Applying grant. target_name: %s grantee_name: %s' % (zgrant.target_name, zgrant.grantee_name))
      logger.info('target_name: %s target_type: %s grantee_name: %s grantee_type: %s right: %s' % \
       (zgrant.target_name, zgrant.target_type, zgrant.grantee_name, zgrant.grantee_type, zgrant.right))
      zr.grantRight(
        target_name = zgrant.target_name,
        target_type = zgrant.target_type,
        grantee_name = zgrant.grantee_name,
        grantee_type = zgrant.grantee_type,
        right = zgrant.right,
      )
    logger.info('%s grant(s) applied successfully!' % len(zgrants))
    if not dlist_zimbra_id:
      response = zr.getDistributionList(dlist_name)
      dlist_zimbra_id = response['GetDistributionListResponse']['dl']['id']
  
    zr.addDistributionListMember(dlist_zimbra_id, [zdelegated_admin_account])

  except ZimbraRequestError, e:
      logger.exception(e)
      self.retry(
        exc = TaskError('Unknown error: %s. Retrying after %s minutes...' % (e, RETRY_TIME)),
        countdown = RETRY_TIME
      )
  
  if celery.app.app_context():
    logger.info('Async task finished. Updating database...')
    domain = Domain.query.filter_by(id = domain_id).one()
    domain.admin_account = zdelegated_admin_account
    try:
      domstate = DomainServiceState.query \
        .filter(DomainServiceState.domain_id == domain_id) \
        .filter(DomainServiceState.service_id == service_id) \
        .one()
    except NoResultFound:
      logger.error('Could not find any domain or services')
      self.retry(
        exc = TaskError('Could not find any domain/serviecs: Retrying after %s minutes...' % RETRY_TIME),
        countdown = RETRY_TIME
      )

    domstate.enabled = True
    domstate.last_sync = datetime.now()
    db.session.commit()
  else:
    raise TaskError('Could not find app context')

@celery.task(bind=True)
def delete_domain_zimbra_task(self, zimbra_config, domain_id, service_id, domain_name):
  """ Delete a domain from Zimbra
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param zimbra_id: ZimbraID of target domain
  :param service_id: Jenova service.id
  :param domain_id: Jenova domain.id 
  """
  logger.info('Starting task delete_domain_zimbra_task...')
  try:
    zr = ZimbraRequest(
      admin_url = zimbra_config['service_api'], 
      admin_user = zimbra_config['admin_user'], 
      admin_pass = zimbra_config['admin_password']
    )
    response = zr.searchDirectory(
      query = '(!(zimbraIsSystemResource=FALSE))', 
      domain_name = domain_name, 
      count_only = True, 
      types='accounts,distributionlists'
    )
    accounts_size = response['SearchDirectoryResponse']['num']
    logger.warning('ACCOUNTS SIZE: %s' % accounts_size)
    if not accounts_size == 0:
      # ERROR
      logger.warning('RAISE TASKERROR')
      raise TaskError('Found %s account(s)/list(s) associated into domain' % accounts_size)
      #self.update_state(
      #  state = states.FAILURE,
      #  meta = { 'result' : 'Found %s account(s) associated into domain' % accounts_size }
      #)
      #return 'Found %s account(s) associated into domain' % accounts_size
    domain_zimbra_id = zr.getDomainId(domain_name)
    zr.deleteDomain(domain_zimbra_id)
  except ZimbraRequestError, e:
    if e.response.get_fault_code() == 'account.NO_SUCH_DOMAIN':
      logger.info('Domain does not exists.')
    else:
      logger.exception(e)
      self.retry(
        exc = TaskError('Unknown error: %s. Retrying after %s minutes...' % (e, RETRY_TIME)),
        countdown = RETRY_TIME
      )

  if celery.app.app_context():
    logger.info('Async task finished. Updating database...')
    domain = Domain.query.filter_by(id = domain_id).one()
    try:
      domstate = DomainServiceState.query \
        .filter(DomainServiceState.domain_id == domain_id) \
        .filter(DomainServiceState.service_id == service_id) \
        .one()
      
    except NoResultFound:
      logger.error('Could not find any domain or services')
      self.retry(
        exc = TaskError('Could not find any domain/services: Retrying after %s minutes...' % RETRY_TIME),
        countdown = RETRY_TIME
      )

    # domstate.enabled = False
    # domstate.last_sync = datetime.now()
    db.session.delete(domstate)
    db.session.commit()
  else:
    raise TaskError('Could not find app context')

# TODO: ...
@celery.task(bind=True)
def update_cos_into_domain_zimbra_task(self, zimbra_config, domain_name, zimbra_cos_id, quota):
  """Update a COS into domain with the given quota
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param domain_name: Name of the domain
  :param zimbra_cos_id: zimbraId of the COS
  :param quota: Max accounts for the given cos
  """
  zr = ZimbraRequest(
    admin_url = zimbra_config['service_api'], 
    admin_user = zimbra_config['admin_user'], 
    admin_pass = zimbra_config['admin_password']
  )
  response = zr.getDomain(domain_name, ['DomainCOSMaxAccounts'])
  zimbra_domain_id = response['GetDomainResponse']['domain']['id']
  for key, value in response['GetDomainResponse']['domain']['a'].items():
    print key, value

  #response = zr.modifyDomain(
  # domain_id = zimbra_domain_id,
  #  attr = ['+DomainCOSMaxAccounts'],
    # {zimbraId-of-a-cos}:{max-accounts}
  #  value = ':'.join((zimbra_cos_id, quota))
  #)

@celery.task(bind=True)
def update_zimbra_domain_report_task(self, zimbra_config, domains, reseller_name):
  """Update Zimbra Account Report to Redis.
  :param zimbra_config: A dict type containing the keys: service_api, admin_user, admin_password
  :param domains: List of domains from a same zimbra service
  """
  config = Config.load()
  redis = StrictRedis(config['redishost'])

  report = ZimbraReport(
    admin_url = zimbra_config['service_api'], 
    admin_user = zimbra_config['admin_user'], 
    admin_pass = zimbra_config['admin_password'],
  )

  
  response = pickle.dumps(report.getEditionReport(domains=domains))
  reseller_key = 'jenova:reports:%s' % reseller_name
  
  with redis.pipeline() as pipe:
    pipe.set(reseller_key, response)
    # pipe.expire(domain_key, 100) # TODO
    pipe.execute()