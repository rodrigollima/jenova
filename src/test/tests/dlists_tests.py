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

class DlistsTestCase(TestCase, BaseTest):

  def setUp(self):
    BaseTest.setUp(self)

    self.dlists_url = '%s/services/%s/domains/%s/dlists' % (self.general['api_url'],
                                self.service_zimbra['name'],
                                self.domain['name'],)
  def tearDown(self):
    BaseTest.tearDown(self)
    
  # -------------------------------------------------------------------- tests
  def test_create_dlist_pass(self):
    # create dlist
    d = json.dumps({
      'dlist' : self.dlists['dlist_valid'],
      'accounts' : self.dlists['accounts'],
    })

    r = requests.post(self.dlists_url, headers=self.general['headers'], 
                      data=d, verify=False)

    if not r.status_code in [201]:
      self.assertTrue(False) 

    print 'PASS: create Dlist'

  def test_create_dlist_fail(self):
    #try create dlist with invalid name/domain
    #PASS if test fails
    d = json.dumps({
      'dlist' : self.dlists['dlist_invalid'],
      'accounts' : self.dlists['accounts'],
    })

    r = requests.post(self.dlists_url, headers=self.general['headers'], 
                      data=d, verify=False)
    
    if not r.status_code in [201]:
      self.assertTrue(True) 

    print 'PASS: fail on create invalid Dlist'
      
  def test_get_dlist_pass(self):
    url_get = self.dlists_url + '/' + self.dlists['dlist_valid']
    r = requests.get(url_get, headers=self.general['headers'], verify=False)
 
    if not r.status_code in [200]:
      self.assertTrue(False)

    print 'PASS: get Dlist retunr result'

  def test_get_dlist_fail(self):
    url_get = self.dlists_url + '/' + self.dlists['dlist_invalid']
    r = requests.get(url_get, headers=self.general['headers'], verify=False)

    if r.status_code == 404:
      self.assertTrue(True)

    print 'PASS: get Dlist invalid, retunr not found'

  def test_get_all_dlist_pass(self):
    url_get = self.dlists_url
    r = requests.get(url_get, headers=self.general['headers'], verify=False)
 
    if not r.status_code in [200]:
      self.assertTrue(False)

    print 'PASS: get Dlist retunr result'
    

  def test_update_dlist_pass(self):
    # update dlist, removing actual members and add news
    d = json.dumps({
      'dlist' : self.dlists['dlist_valid'],
      'accounts' : self.dlists['accounts_to_update'],
    })

    url_put = self.dlists_url + '/' + self.dlists['dlist_valid']
    r = requests.put(url_put, headers=self.general['headers'], 
                      data=d, verify=False)

    if not r.status_code in [201]:
      self.assertTrue(False) 

    print 'PASS: Updated Dlist'    
    
  def test_update_dlist_fail(self):
    # try update invalid dlist, 
    # Pass when test fails

    d = json.dumps({
      'dlist' : self.dlists['dlist_invalid'],
      'accounts' : self.dlists['accounts_to_update'],
    })

    url_put = self.dlists_url + '/' + self.dlists['dlist_invalid']
    r = requests.put(url_put, headers=self.general['headers'], 
                      data=d, verify=False)

    if r.status_code == 400:
      self.assertTrue(True) 

    print 'PASS: Updated Dlist fails on update invalid dlist'    

  def test_delete_dlist_pass(self):
    url_put = self.dlists_url + '/' + self.dlists['dlist_valid']
    r = requests.delete(url_put, headers=self.general['headers'],verify=False)

    if r.status_code == 204:
      self.assertTrue(True) 

    print 'PASS: Delete Dlist Sucessful'    

  def test_delete_dlist_fail(self):
    url_put = self.dlists_url + '/' + self.dlists['dlist_invalid']
    r = requests.delete(url_put, headers=self.general['headers'],verify=False)

    if not r.status_code == 204:
      self.assertTrue(True) 

    print 'PASS: Try delete Dlist invalid fails'    

if __name__ == "__main__":
  unittest.main()