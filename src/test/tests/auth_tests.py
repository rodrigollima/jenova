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

    self.users_url = '%s/users/%s' % (self.general['api_url'], self.user['name'])

  def tearDown(self):
    BaseTest.tearDown(self)
    
  # -------------------------------------------------------------------- tests
  def test_create_auth(self):
    # clean up
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

  def test_get_auth(self):
    r = requests.get(self.reseller_url, headers=self.general['headers'], verify=False)
    
    if r.status_code != 200:
      print r.text
      print r.status_code
      self.assertTrue(False)
    
    print 'PASS: get reseller'

    r = requests.get(self.client_url, headers=self.general['headers'], verify=False)
    
    if r.status_code != 200:
      print r.text
      print r.status_code
      self.assertTrue(False)

    print 'PASS: get client'   
    
if __name__ == "__main__":
  unittest.main()