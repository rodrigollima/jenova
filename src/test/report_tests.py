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
  def test_get_report(self):
    r = requests.get(self.report_url, headers=self.general['headers'], verify=False)
    # print json.dumps(r.json(), indent=2)
    print r.text
    # if r.status_code != 200:
    #   print r.text
    #   print r.status_code
    #   self.assertTrue(False)

    # print 'PASS: get zimbra report'
    
if __name__ == "__main__":
  unittest.main()