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
    # BEFORE RUN TESTS
    BaseTest.setUp(self)

  def tearDown(self):
    # AFTER RUN TESTS
    BaseTest.tearDown(self)

  def test_create_template(self):
    # YOUR TEST HERE
    pass

  # -------------------------------------------------------------------- tests
  def test_get_template(self):
    # YOUR TEST HERE
    pass
  
  def test_delete_template(self):
    # YOUR TEST HERE
    pass


if __name__ == "__main__":
  unittest.main()