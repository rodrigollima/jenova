from test.base import BaseTest
import unittest, socket, requests, json
from time import sleep
from unittest import TestCase

# supress ssl warnings.
requests.packages.urllib3.disable_warnings(
    requests
    .packages
    .urllib3
    .exceptions
    .InsecureRequestWarning) 

class AuthTestCase(TestCase, BaseTest):
  # ------------------------------------------------------------------ unbound
  def setUp(self):
    BaseTest.setUp(self)
    
    self.reseller_url = '%s/resellers/%s' % (self.general['api_url'],
                                self.reseller['name'])

    self.client_url = '%s/clients/%s' % (self.reseller_url,
                                self.client['name'])

    self.users_url = '%s/users/%s' % (self.general['api_url'], 
                                self.user['name'])

    self.service_zimbra_url = '%s/service/%s' % (self.general['api_url'], 
                                self.service_zimbra['name'])

    self.service_dns_url = '%s/service/%s' % (self.general['api_url'], 
                                self.service_dns['name'])

    self.service_mxhero_url = '%s/service/%s' % (self.general['api_url'], 
                                self.service_mxhero['name'])

    self.domain_url = '%s/clients/%s/domains/%s' % (self.general['api_url'],
                                self.client['name'],
                                self.domain['name'])                     
                                           
    self.sync_zimbra_url = '%s/services/%s/domains/%s' % (self.general['api_url'],
                                self.service_zimbra['name'],
                                self.domain['name'])
  def tearDown(self):
    BaseTest.tearDown(self)
    
  # -------------------------------------------------------------------- tests
  def test_create_auth(self):
    # clean up
    requests.delete(self.domain_url + '?force=1', headers=self.general['headers'], verify=False)
    requests.delete(self.service_zimbra_url, headers=self.general['headers'], verify=False)
    requests.delete(self.service_dns_url, headers=self.general['headers'], verify=False)
    requests.delete(self.service_mxhero_url, headers=self.general['headers'], verify=False)
    requests.delete(self.client_url, headers=self.general['headers'], verify=False)
    requests.delete(self.reseller_url, headers=self.general['headers'], verify=False)


    # create reseller
    d = json.dumps({
      'company' : self.reseller['company'],
      'email' : self.reseller['email'],
      'login' : self.reseller['login'],
      'login_name' : self.reseller['login_name'],
      'password' : self.reseller['password']
    })

    r = requests.post(self.reseller_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)
    
    print 'PASS: create reseller'

    # create client
    d = json.dumps({
      'company' : self.client['company'],
      'email' : self.client['email'],
      'login' : self.client['login'],
      'login_name' : self.client['login_name'],
      'password' : self.client['password']
    })

    r = requests.post(self.client_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create client'

    # create user
    d = json.dumps({
      'client_name' : self.user['client_name'],
      'password' : self.user['password'],
      'name' : self.user['display'],
      'email' : self.user['email']
    })

    r = requests.post(self.users_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create user'


    # create service zimbra
    d = json.dumps({
      'service_host' : self.service_zimbra['service_host'],
      'service_type' : self.service_zimbra['service_type'],
      'service_desc' : self.service_zimbra['service_desc'],
      'service_api' : self.service_zimbra['service_api'],
      'credentials_identity' : self.service_zimbra['credentials_identity'],
      'credentials_secret' : self.service_zimbra['credentials_secret']
    })

    r = requests.post(self.service_zimbra_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create zimbra service'

    # create service dns
    d = json.dumps({
      'service_host' : self.service_dns['service_host'],
      'service_type' : self.service_dns['service_type'],
      'service_desc' : self.service_dns['service_desc'],
      'service_api' : self.service_dns['service_api'],
      'credentials_secret' : self.service_dns['credentials_secret']
    })

    r = requests.post(self.service_dns_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create dns service'

    # create service mxhero
    d = json.dumps({
      'service_host' : self.service_mxhero['service_host'],
      'service_type' : self.service_mxhero['service_type'],
      'service_desc' : self.service_mxhero['service_desc'],
      'service_api' : self.service_mxhero['service_api']
    })

    r = requests.post(self.service_mxhero_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create mxhero service'

    # create domain
    d = json.dumps({})
    r = requests.post(self.domain_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 201 and r.status_code != 409:
      print r.text
      print r.status_code
      self.assertTrue(False)     

    print 'PASS: create domain'

    # activate zimbra
    d = json.dumps({})
    r = requests.put(self.sync_zimbra_url, headers=self.general['headers'], 
                            data=d,
                            verify=False)

    if r.status_code != 202:
      print r.text
      print r.status_code
      self.assertTrue(False)

    root_job_id, parent_job_id = r.json()['response']['tasks_id']
    for job in [(root_job_id, 'createzimbradomains'), (parent_job_id, 'createdelegatedzimbra')]:
      job_id, task_type = job
      state_pending = True
      while state_pending:
        domain_task_url = self.general['api_url'] + '/tasks/%s/id/%s' % (task_type, job_id)
        r = requests.get(domain_task_url, headers=self.general['headers'], verify=False)
        if r.json()['response']['task_state'] != 'PENDING':
          state_pending = False
        print job_id, r.json()['response']['task_state']
        sleep(2)

    print 'PASS: activating zimbra'
  # def test_get_auth(self):
  #   r = requests.get(self.reseller_url, headers=self.general['headers'], verify=False)
    
  #   if r.status_code != 200:
  #     print r.text
  #     print r.status_code
  #     self.assertTrue(False)
    
  #   print 'PASS: get reseller'

  #   r = requests.get(self.client_url, headers=self.general['headers'], verify=False)
    
  #   if r.status_code != 200:
  #     print r.text
  #     print r.status_code
  #     self.assertTrue(False)

  #   print 'PASS: get client'   
    
if __name__ == "__main__":
  unittest.main()