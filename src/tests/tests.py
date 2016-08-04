import unittest, sys, requests, json, uuid, time, socket, random
from datetime import datetime, timedelta
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # supress ssl warnings.

TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJRQSBBZG1pbiIsImFkbWluIjpmYWxzZSwiYXBpX2VuYW\
JsZWQiOnRydWUsImFwaV9hY2Nlc3MiOltdLCJlbmFibGVkIjp0cnVlLCJlbWFpbCI6InNhbmRyby5tZWxsb0Bpbm92YS5uZXQiLCJjcmVhdGVfdG\
ltZSI6IjIwMTUtMTItMjBUMTY6MzU6MjQrMDA6MDAiLCJjbGllbnRfaWQiOm51bGwsImdsb2JhbF9hZG1pbiI6dHJ1ZSwibG9naW4iOiJxYV9hZG\
1pbiIsImlkIjoxLCJwZXJtaXNzaW9ucyI6W119fQ.45zCR4RFf2_Fi_hSWXsd1KnIQzaWPzMeZMmyVjeMm8M'



CLIENT_NAME = 'inovatec'
RESELLER_NAME = 'inovatec'
RESELLER_NAME2 = 'jenova'
CLIENT_NAME2 = 'jenova'
API_SERVER = socket.gethostbyname(socket.gethostname())
BASEURL = 'https://%s:8443' % API_SERVER
HEADERS = {
  'Content-Type' : 'application/json',
  'Authorization' : 'Bearer %s' % TOKEN
}

class ClientTestCase(unittest.TestCase):
  def test_auth_crud_operations(self):
    DOMAIN_NAME = 'jenova.com.br'
    inova_reseller = BASEURL + '/resellers/%s' % RESELLER_NAME
    domain_url = BASEURL + '/clients/%s/domains/%s' % (CLIENT_NAME, DOMAIN_NAME)
    service_hosted_url = BASEURL + '/service/hostedzimbra'
    service_dns_url = BASEURL + '/service/dns'
    service_mxhero_url = BASEURL + '/service/mxhero'
    request_data = {
      'company' : 'Inova Tecnologias S.A',
      'email' : 'operacao@inova.net',
      'login' : 'johndoe',
      'login_name' : 'John Doe Reseller Login',
      'password' : 'jenova'
    }
    print 'Getting resellers...'
    r = requests.get(BASEURL + '/resellers', headers=HEADERS, verify=False)
    print r.status_code, r.text

    print 'Creating reseller %s...' % RESELLER_NAME
    r = requests.delete(inova_reseller, headers=HEADERS, verify=False)
    print r.status_code

    response = requests.post(inova_reseller, headers=HEADERS, verify=False, data=json.dumps(request_data))
    if response.status_code != 201 and response.status_code != 409:
      print response.status_code
      self.assertTrue(False)

    request_data['company'] = 'jenova do Brasil Inc.'
    request_data['email'] = 'missbrasil@jenova.com.br'
    request_data['login'] = 'patricia.galdino'
    request_data['login_name'] = 'Patricia Galdino'
    inova_reseller2 = BASEURL + '/resellers/%s' % RESELLER_NAME2

    print 'Creating reseller %s...' % RESELLER_NAME2
    r = requests.delete(inova_reseller2, headers=HEADERS, verify=False)
    print r.status_code

    response = requests.post(inova_reseller2, headers=HEADERS, verify=False, data=json.dumps(request_data))
    if response.status_code != 201:
      print response.status_code
      print response.text
      self.assertTrue(False)

    print 'Creating client %s ...' % CLIENT_NAME2
    request_data['company'] = 'Inova Tecnologias Client Inc.'
    request_data['email'] = 'sandromll@gmail.com'
    request_data['login'] = 'johndoe_client'
    request_data['login_name'] = 'John Doe Client Login'

    inova_client_uri = inova_reseller + '/clients/%s' % CLIENT_NAME2
    response = requests.post(inova_client_uri, data=json.dumps(request_data), headers=HEADERS, verify=False)
    if response.status_code != 201 and response.status_code != 409:
      print response.status_code
      print response.text
      self.assertTrue(False)

    print response.status_code
    print response.json()

    print 'Creating client %s ...' % CLIENT_NAME
    request_data['company'] = 'Inova Tecnologias Clients Inc.'
    request_data['email'] = 'sandromll@gmail.com'
    request_data['login'] = 'inovatec_login'
    request_data['login_name'] = 'Inovatec Login'

    inova_client_uri = inova_reseller + '/clients/%s' % CLIENT_NAME
    response = requests.post(inova_client_uri, data=json.dumps(request_data), headers=HEADERS, verify=False)
    if response.status_code != 201 and response.status_code != 409:
      print response.status_code
      print response.text
      self.assertTrue(False)

    print response.status_code
    print response.json()

    print 'Creating domain %s ...' % DOMAIN_NAME

    requests.delete(domain_url, headers=HEADERS, verify=False)
    requests.delete(service_hosted_url, headers=HEADERS, verify=False)
    requests.delete(service_dns_url, headers=HEADERS, verify=False)
    requests.delete(service_mxhero_url, headers=HEADERS, verify=False)


    #r = requests.post(client_url, headers=HEADERS, verify=False, data=json.dumps(request_data))
    #print r.text, r.status_code

    # Add Zimbra Service
    request_data = json.dumps({
      'service_host' : '54.165.130.169',
      'service_type' : 'ZIMBRA',
      'service_desc' : 'Zimbra',
      'service_api' : 'https://%s:7071/service/admin/soap' % API_SERVER,
      'credentials_identity' : 'admin@jenova.com',
      'credentials_secret' : 'zpassword'
    })
    r = requests.post(service_hosted_url, headers=HEADERS, verify=False, data=request_data)

    # Add DNS Service
    request_data = json.dumps({
      'service_host' : '%s:8081' % API_SERVER,
      'service_type' : 'DNS',
      'service_desc' : 'DNS',
      'service_api' : '%s:8081' % API_SERVER,
      'credentials_secret' : 'changeme'
    })

    r = requests.post(service_dns_url, headers=HEADERS, verify=False, data=request_data)
    print r.text, r.status_code

    # Add mxHero Service
    request_data = json.dumps({
      'service_desc' : 'mxHero',
      'service_host' : '%s' % API_SERVER,
      'service_name' : 'MxHero',
      'service_type' : 'MXHERO'
    })

    r = requests.post(service_mxhero_url, headers=HEADERS, verify=False, data=request_data)
    print r.text, r.status_code

    '''
    request_data = json.dumps({
      'services' : ['dns', 'hostedzimbra']
    })

    r = requests.post(domain_url, headers=HEADERS, verify=False, data=request_data)
    print r.text, r.status_code
    '''


    # Create new user
    request_data = {
      'client_name' : CLIENT_NAME2,
      'password' : 'jenova',
      'name' : 'Iteclogin2 User',
      'email' : 'sandro.mello@inova.net'
    }
    request_data = json.dumps(request_data)
    LOGIN = 'iteclogin2'

    print 'Creating new user %s ...' % LOGIN
    auth_uri = BASEURL + '/users/%s' % LOGIN
    print 'POST:', auth_uri
    response = requests.post(auth_uri, headers=HEADERS, verify=False, data=request_data)
    if response.status_code != 201 and response.status_code != 409:
      print response.status_code
      print response.text
      self.assertTrue(False)
    print response.status_code

    auth_uri = BASEURL + '/users/%s' % LOGIN
    print 'GET:', auth_uri
    response = requests.get(auth_uri + '?filter_by=login', headers=HEADERS, verify=False)
    print response.status_code, response.text

    print 'Changing password for user %s' % LOGIN
    change_password_uri = BASEURL + '/users/%s' % LOGIN
    print 'PUT:', change_password_uri

    request_data = json.dumps({
      'password' : 'jenova',
      'email' : 'sandromll@gmail.com',
      'desc' : 'Test login'
    })
    response = requests.put(change_password_uri, headers=HEADERS, verify=False, data=request_data)
    if response.status_code != 204:
      print response.status_code
      self.assertTrue(False)
    print response.status_code

    print 'Setting global admin into account %s...' % LOGIN
    user_global_admin = BASEURL + '/users/%s/globaladmin' % LOGIN
    r = requests.post(user_global_admin, headers=HEADERS, verify=False)
    print r.status_code

    print 'Enabling API for account %s...' % LOGIN
    user_api_enabled = BASEURL + '/users/%s/api' % LOGIN
    r = requests.post(user_api_enabled, headers=HEADERS, verify=False)
    print r.status_code

    print 'Enabling admin for account %s...' % LOGIN
    user_admin = BASEURL + '/users/%s/admin' % LOGIN
    r = requests.post(user_admin, headers=HEADERS, verify=False)
    print r.status_code
    print r.text

    r = requests.delete(user_admin, headers=HEADERS, verify=False)
    print r.status_code
    print r.text

    print 'DELETE:', auth_uri

    r = requests.get(BASEURL + '/users', headers=HEADERS, verify=False)
    print r.status_code
    print r.text
    #response = requests.delete(auth_uri + '?filter_by=login', headers=HEADERS, verify=False)
    #print response.status_code

    self.assertTrue(response.status_code == 204)

  def test_scope_crud_operations(self):
    scopes = ['dns', 'domain', 'store', 'users', 'service', 'client',
                'zimbra_login_delegated', 'manage_zimbra_login_delegated', 'permissions']
    scope_url = BASEURL + '/scopes'
    for scope_name in scopes:
      r = requests.post('%s/%s' % (scope_url, scope_name), data=json.dumps({}), headers=HEADERS, verify=False)
      print r.status_code,
      if r.status_code == 201:
        print json.dumps(r.json(), indent=2)

    r = requests.get(scope_url, headers=HEADERS, verify=False)
    print r.status_code,
    print json.dumps(r.json(), indent=2)

  def test_permissions_crud_operations(self):
    USER = 'iteclogin2'
    SCOPES = ['dns', 'domain', 'permissions']
    request_data = {
      'read' : True,
      'write' : True,
      'delete' : True,
      'edit' : True
    }
    for scope in SCOPES:
      perm_url = BASEURL + '/scopes/%s/users/%s/permissions' % (scope, USER)
      if scope == 'dns':
        request_data['edit'] = False
      else:
        request_data['edit'] = True
      r = requests.put(perm_url, data=json.dumps(request_data), headers=HEADERS, verify=False)
      print r.status_code,
      print json.dumps(r.json(), indent=2)

    for scope in SCOPES:
      perm_url = BASEURL + '/scopes/%s/users/%s/permissions' % (scope, USER)
      r = requests.delete(perm_url + '/delete', headers=HEADERS, verify=False)
      print 'READ',
      print r.status_code


    #r = requests.get(perm_url, headers=HEADERS, verify=False)
    #print r.status_code,
    #print json.dumps(r.json(), indent=2)

  def test_get_all_users(self):
    user_url = BASEURL + '/users'
    response = requests.get(user_url, headers=HEADERS, verify=False)
    print response.status_code
    print json.dumps(response.json(), indent=2)

    #client_url = BASEURL + '/reseller/all/client/all'
    #response = requests.get(client_url, headers=HEADERS, verify=False)
    #print json.dumps(response.json(), indent=2)

  def test_domain_crud_operations(self):
    print 'Creating domains for client %s...' % CLIENT_NAME
    DOMAINS = [ 'inova.net', 'tecnolomula.com.br', 'stackeme.io', 'stackme.com.br']
    for dom in DOMAINS:
      dom_url = BASEURL + '/clients/%s/domains/%s' % (CLIENT_NAME, dom)
      requests.delete(dom_url, headers=HEADERS, verify=False)

      # Create an empty domain without services
      r = requests.post(dom_url, data=json.dumps({}), headers=HEADERS, verify=False)
      if r.status_code != 201:
        print r.text
        self.assertTrue(False)
      print r.status_code,

    request_data = {}


    DOMAINS2 = ['domin.com.br', 'domain2.com.br', 'dududu.io', 'rastraz.sa', 'samanco.io',
    'dadada.com', 'popopo.me', 'papapa.info', 'jenova.com.br', 'sargento.io',
    'paulwalki.com', 'inova.com.br', 'rapadura.io', 'kone.io', 'salamandra.io',
    'stackso.me', 'lavajato.io', 'lula.io', 'pagando.me', 'rouba.me', 'rex.me',
    'xandar.sa', 'xmen.sa', 'roupanova.se', 'integrando.se', 'queroquero.me'
    ]
    #DOMAINS2 = open('domains.txt', 'r').read().split()

    for dom in DOMAINS2:
      print 'Creating domain %s for client %s...' % (dom, CLIENT_NAME2)
      dom_url = BASEURL + '/clients/%s/domains/%s' % (CLIENT_NAME2, dom)
      requests.delete(dom_url + '?force=1', headers=HEADERS, verify=False)

      if dom == 'paulwalki.com':
        request_data = { 'services' : ['dns', 'hostedzimbra'] }
      elif dom == 'jenova.com.br':
        request_data = { 'services' : ['dns', 'hostedzimbra'] }
      else:
        request_data = {}

      # Create an empty domain without services
      r = requests.post(dom_url, data=json.dumps(request_data), headers=HEADERS, verify=False)
      if r.status_code != 201:
        print r.text
        self.assertTrue(False)
      print r.status_code,

    domains_url = BASEURL + '/clients/%s/domains' % CLIENT_NAME
    domains_url2 = BASEURL + '/clients/%s/domains' % CLIENT_NAME2

    r = requests.get(domains_url, headers=HEADERS, verify=False)
    r2 = requests.get(domains_url2, headers=HEADERS, verify=False)
    if r.status_code != 200 or r2.status_code != 200:
      print r.text, r2.text
      self.assertTrue(False)
    print json.dumps(r.json(), indent=2)
    print json.dumps(r2.json(), indent=2)

    reseller_domains = BASEURL + '/resellers/%s/domains' % RESELLER_NAME
    r = requests.get(reseller_domains, headers=HEADERS, verify=False)
    if r.status_code != 200:
      print r.text
      self.assertTrue(False)
    print json.dumps(r.json(), indent=2)

    for dom in ['paulwalki.com', 'jenova.com.br']:
      # Turn on dns service to domains in list
      state_domain_url = BASEURL + '/clients/%s/domains/%s/services/dns' % (CLIENT_NAME2, dom)
      r = requests.put(state_domain_url, data=json.dumps({'enable' : True}), headers=HEADERS, verify=False)
      if r.status_code != 204:
        print r.text
        self.assertTrue(False)

    print 'Getting domain states...'
    state_domain_url = BASEURL + '/clients/%s/domains/paulwalki.com/services' % CLIENT_NAME2
    r = requests.get(state_domain_url, headers=HEADERS, verify=False)
    if r.status_code != 200:
      print r.text
      self.assertTrue(False)
    print json.dumps(r.json(), indent=2)

  def test_domain_sync_service(self):
    DOMAIN = 'paulwalki.com'
    domain_sync = BASEURL + '/services/%s/domains/%s' % ('hostedzimbra', DOMAIN)
    r = requests.put(domain_sync, data=json.dumps({}), headers = HEADERS, verify=False)
    if r.status_code != 202:
      print r.text
      self.assertTrue(False)
    print r.status_code, json.dumps(r.json(), indent=2)

    import time
    #time.sleep(10)
    root_job_id, parent_job_id = r.json()['response']['tasks_id']

    for job in [(root_job_id, 'createzimbradomains'), (parent_job_id, 'createdelegatedzimbra')]:
      job_id, task_type = job
      state_pending = True
      while state_pending:
        domain_task_url = BASEURL + '/tasks/%s/id/%s' % (task_type, job_id)
        r = requests.get(domain_task_url, headers = HEADERS, verify=False)
        if r.json()['response']['task_state'] != 'PENDING':
          state_pending = False
        print job_id, r.json()['response']['task_state']
        time.sleep(1)

  def test_login_operation(self):
    login_url = BASEURL + '/login'

    request_data = json.dumps({'username' : 'iteclogin2', 'password' : 'p@ssw0rd'})
    r = requests.post(login_url, data = request_data, headers = HEADERS, verify=False)
    print r.status_code
    print json.dumps(r.json(), indent=2)

    r = requests.get(BASEURL + '/user/all', headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

  def test_service_crud_operations(self):

    print 'getting all services...'
    url = BASEURL + '/service/all'
    r = requests.get(url, headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)


    print 'creating zimbratest service...'
    url = BASEURL + '/service/zimbratest'
    request_data = json.dumps({
      'service_host' : '1.1.1.1',
      'service_desc' : 'Zimbra Test',
      'service_type' : 'ZIMBRA',
      'service_api' : 'https://1.1.1.1:7071/service/admin/soap',
      'credentials_identity' : 'email@domain.com',
      'credentials_secret' : 'secure'
    })

    r = requests.post(url, data = request_data, headers = HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    print 'deleting zimbratest service...'
    r = requests.delete(url, headers = HEADERS, verify=False)
    print r.status_code

  def test_notices_crud_operations(self):
    service_name = 'hostedzimbra'
    url = BASEURL + '/service/%s/notices' % service_name
    started_at = datetime.now() - timedelta(days=2)
    ended_at = datetime.now()

    request_data = json.dumps({
      'author' : 'qa_admin',
      'started_at' : str(started_at),
      'ended_at' : str(ended_at),
      'notice_type' : 'maintenance',
      'description' : 'Falha em dois discos em um storage de alta performance que degradou o throughput de escrita.'
    })

    r = requests.post(url, data = request_data, headers = HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    r = requests.post(url, data = request_data, headers = HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    r = requests.get(url, headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    notice_id = r.json()['response'][0]['id']
    delete_url = url + '/%s' % notice_id
    r = requests.delete(delete_url, headers=HEADERS, verify=False)
    #print json.dumps(r.json(), indent=2)



  def test_dns_service_crud_operations(self):
    dns_url = BASEURL + '/service/dns/zone/jenova.com.br'

    #delete SOA
    print 'deleting SOA...'
    try:
      r = requests.delete(dns_url, headers = HEADERS, verify=False)
      print r.status_code, json.dumps(r.json(), indent=2)
    except:
      pass
    # create SOA
    print 'creating SOA...'
    r = requests.post(dns_url, headers = HEADERS, verify=False)
    print r.status_code, json.dumps(r.json(), indent=2)

    # create A record
    print 'creating A records'
    dns_a_type_url = dns_url + '/type/a/name/jenova.com.br'
    for i in range(0, 9):
      request_data = {
        'content' : '177.154.154.6%s' % i,
        'ttl' : 300
      }
      r = requests.post(dns_a_type_url, data=json.dumps(request_data), headers = HEADERS, verify=False)
      print r.status_code, json.dumps(r.json(), indent=2)

    # create CNAME record
    cname_records = {
      'webmail.jenova.com.br' : 'webmail.u.inova.com.br',
      'pop.jenova.com.br' : 'pop.u.inova.com.br',
      'imap.jenova.com.br' : 'imap.u.inova.com.br',
      'smtp.jenova.com.br' : 'smtp.u.inova.com.br',
      'mail.jenova.com.br' : 'webmail.u.inova.com.br'
    }

    for name, content in cname_records.iteritems():
      print 'creating CNAME record %s:%s' % (name, content)
      dns_cname_url = dns_url + '/type/cname/name/%s' % name
      request_data = {
        'content' : content,
        'ttl' : 300
      }
      r = requests.post(dns_cname_url, data=json.dumps(request_data), headers = HEADERS, verify=False)
      print r.status_code, json.dumps(r.json(), indent=2)


    # RR update
    request_data = {
       'old_content' : '177.154.154.66',
       'old_ttl' : 200,
       'new_registry_name' : 'jenova.com.br',
       'new_content' : '177.154.154.199',
       'new_ttl' : 3600
    }

    dns_a_type_url = dns_url + '/type/A/name/jenova.com.br'
    r = requests.put(dns_a_type_url, data=json.dumps(request_data), headers = HEADERS, verify=False)


    # Simple update
    request_data = {
       'old_content' : 'webmail.u.inova.com.br',
       'old_ttl' : 300,

       'new_registry_name' : 'edited.jenova.com.br',
       'new_content' : 'edited.jenova.com.br',
       'new_ttl' : 501
    }

    dns_cname_type_url = dns_url + '/type/cname/name/webmail.jenova.com.br'
    r = requests.put(dns_cname_type_url, data=json.dumps(request_data), headers = HEADERS, verify=False)

    # get domain entries
    print 'getting domain'
    r = requests.get(dns_url, headers = HEADERS, verify=False)
    print r.status_code, json.dumps(r.json(), indent=2)

  def test_dns_backup_restore_operations(self):
    url = BASEURL + '/service/dns/zone/jenova.com.br'

    # Create backup
    data = {}
    dns_backup = url + '/backup'
    r = requests.post(dns_backup, data=json.dumps(data), headers = HEADERS, verify=False)
    print r.status_code, json.dumps(r.json(), indent=2)

    # get backup
    r = requests.get(dns_backup, headers = HEADERS, verify=False)
    print r.status_code, json.dumps(r.json(), indent=2)

    # restore backup
    data = {'backup_id' : 1}
    r = requests.put(dns_backup, data=json.dumps(data), headers = HEADERS, verify=False)
    print r.status_code, json.dumps(r.json(), indent=2)

  def test_service_enable(self):
    dom = 'jenova.com.br'
    # Turn on dns service to domains in list
    state_domain_url = BASEURL + '/clients/%s/domains/%s/services/dns' % (CLIENT_NAME2, dom)
    r = requests.put(state_domain_url, data=json.dumps({'enable' : True}), headers=HEADERS, verify=False)
    if r.status_code != 204:
      print r.text
      self.assertTrue(False)

  def test_preauth(self):
    DOMAIN_NAME = 'paulwalki.com'
    preauth_url = BASEURL + '/services/hostedzimbra/domains/%s/preauth' % DOMAIN_NAME
    r = requests.get(preauth_url, headers = HEADERS, verify = False, allow_redirects = False)
    #print r.headers['location']
    #time.sleep(5)
    #preauth_url = BASEURL + '/services/hostedzimbra/domains/jenova.com.br/preauth'
    #r = requests.get(preauth_url, headers = HEADERS, verify=False, verify = False, allow_redirects = False)
    print r.status_code,
    print r.headers['location']

  def test_external_accounts(self):
    DOMAIN_NAME = 'paulwalki.com'
    ACCOUNT_NAME = '%s@%s' % (uuid.uuid4().hex, DOMAIN_NAME)
    
    print 'creating %s...' % ACCOUNT_NAME
    url = BASEURL + '/services/hostedzimbra/domains/%s/accounts/%s' % (DOMAIN_NAME, ACCOUNT_NAME)
    data = {
      'displayName' : 'Conta Teste',
      'sn' : 'Teste',
      'userPassword' : 'jenova',
      'zimbraAccountStatus' : 'active',
      'zimbraId' : 'anything_this_should_be_skipped_by_backend',
      'zimbraCOSId' : ''
    }

    r = requests.post(url, headers = HEADERS, verify=False, data=json.dumps(data))
    print r.status_code
    print json.dumps(r.json(), indent=2)

    
    print 'getting all accounts from %s' % DOMAIN_NAME
    url = BASEURL + '/services/hostedzimbra/domains/%s/accounts' % DOMAIN_NAME
    r = requests.get(url, headers = HEADERS, verify=False)
    print r.status_code
    print json.dumps(r.json(), indent=2)

    print 'getting specific account %s' % ACCOUNT_NAME
    url = BASEURL + '/services/hostedzimbra/domains/%s/accounts/%s' % (DOMAIN_NAME, ACCOUNT_NAME)
    r = requests.get(url, headers = HEADERS, verify=False)
    print r.status_code
    print json.dumps(r.json(), indent=2)
    zimbra_id = str(r.json()['response'][0]['zimbraId'])


    data = {
      'displayName' : 'Conta Teste',
      'sn' : 'Teste',
      'userPassword' : 'jenova',
      'zimbraAccountStatus' : 'active',
      'zimbraId' : zimbra_id
    }

    print 'modifying account %s...' % ACCOUNT_NAME
    r = requests.put(url, headers = HEADERS, verify=False, data=json.dumps(data))
    print r.status_code
    print json.dumps(r.json(), indent=2)


    print 'deleting %s...' % ACCOUNT_NAME
    url = BASEURL + '/services/hostedzimbra/domains/%s/accounts/%s' % (DOMAIN_NAME, ACCOUNT_NAME)
    r = requests.delete(url, headers = HEADERS, verify=False)
    self.assertTrue(r.status_code == 204)
    print r.status_code

  def test_domain_cos_crud_operations(self):
    pass
    url = BASEURL + '/services/hostedzimbra/domains/jenova.com.br/cos'
    r = requests.get(url, headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)
    

    # limit1 = random.randint(1, 100)
    # limit2 = random.randint(1, 100)

    # rdata = json.dumps({
    #   'cos' : [
    #     { 'id' : '8e97e282-8aa0-4ac4-96fb-7e2e7620c0a4', 'limit' : limit1 },
    #     { 'id' : '841b8df9-7406-4231-bb7b-175959ff8f9b', 'limit' : limit2 }]
    # })

    # r2 = requests.put(url, data = rdata, headers=HEADERS, verify=False)
    # print json.dumps(r2.json(), indent=2)

    # r = requests.get(url, headers=HEADERS, verify=False)
    # print json.dumps(r.json(), indent=2)

  def test_external_domain(self):
    DOMAIN_NAME = 'paulwalki.com'
    url = BASEURL + '/services/hostedzimbra/domains/%s/status' % DOMAIN_NAME
    
    print 'suspending external domain %s ' % DOMAIN_NAME
    rdata = json.dumps({
      'status' : 'suspended'
    })
    r = requests.put(url, data = rdata, headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    print 'getting external domain status %s' % DOMAIN_NAME
    r = requests.get(url, headers = HEADERS, verify=False)
    print r.status_code
    print json.dumps(r.json(), indent=2)

    print 'activating external domain %s ' % DOMAIN_NAME
    rdata = json.dumps({
      'status' : 'active'
    })
    r = requests.put(url, data = rdata, headers=HEADERS, verify=False)
    print json.dumps(r.json(), indent=2)

    print 'getting external domain status %s' % DOMAIN_NAME
    r = requests.get(url, headers = HEADERS, verify=False)
    print r.status_code
    print json.dumps(r.json(), indent=2)

if __name__ == '__main__':
  suite = unittest.TestSuite()
  suite.addTest(ClientTestCase('test_auth_crud_operations'))
  suite.addTest(ClientTestCase('test_scope_crud_operations'))
  suite.addTest(ClientTestCase('test_permissions_crud_operations'))
  suite.addTest(ClientTestCase('test_domain_crud_operations'))
  suite.addTest(ClientTestCase('test_service_crud_operations'))
  suite.addTest(ClientTestCase('test_notices_crud_operations'))
  suite.addTest(ClientTestCase('test_domain_sync_service'))
  suite.addTest(ClientTestCase('test_service_enable'))
  suite.addTest(ClientTestCase('test_dns_service_crud_operations'))
  suite.addTest(ClientTestCase('test_dns_backup_restore_operations'))
  suite.addTest(ClientTestCase('test_preauth'))
  suite.addTest(ClientTestCase('test_external_accounts'))
  suite.addTest(ClientTestCase('test_external_domain'))
  suite.addTest(ClientTestCase('test_domain_cos_crud_operations'))

  unittest.TextTestRunner().run(suite)
