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

class ReportTestCase(TestCase, BaseTest):
  # ------------------------------------------------------------------ unbound
  def setUp(self):
    BaseTest.setUp(self)

    #/reports/resellers/<reseller_name>/services/<service_name>/domains/<domain_name>
    self.report_url = '%s/reports/resellers/%s' % (
                                self.general['api_url'],
                                self.reseller['name'])

  def tearDown(self):
    BaseTest.tearDown(self)

  # -------------------------------------------------------------------- tests
def test_get_reseller_report(self):
    r = requests.get(self.reseller_report_url, headers=self.general['headers'], verify=False)
    
    if r.status_code != 200:
      print r.text
      print r.status_code
      self.assertTrue(False)

    print 'PASS: get reseller report'
  
  def test_get_domain_report(self):
    r = requests.get(self.domain_report_url, headers=self.general['headers'], verify=False)
    
    if r.status_code != 200:
      print r.text
      print r.status_code
      self.assertTrue(False)

    print 'PASS: get domain report'

  def test_sync_report(self):
    rdata = json.dumps({'sync' : 1})
    r = requests.post(self.reseller_report_url, data=rdata,headers=self.general['headers'], verify=False)
    if r.status_code != 201:
      print r.text
      print r.status_code
      self.assertTrue(False)

    print 'PASS: update zimbra usage report'
    
if __name__ == "__main__":
  unittest.main()