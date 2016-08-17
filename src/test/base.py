import yaml



class BaseTest(object):    
  def setUp(self):
    with open("properties.yaml") as f:
      self.cfg = yaml.safe_load(f)

    self.general = self.cfg['general']
    self.reseller = self.cfg['reseller']
    self.client = self.cfg['client']
    self.service_zimbra = self.cfg['service_zimbra']
    self.service_mxhero = self.cfg['service_mxhero']
    self.service_dns = self.cfg['service_dns']
    self.user = self.cfg['user']
    self.domain = self.cfg['domain']
    self.dlists = self.cfg['dlists']

    self.general['headers'] = {
      'Content-Type' : 'application/json',
      'Authorization' : 'Bearer %s' % self.general['token']
    }

  def tearDown(self):
    pass