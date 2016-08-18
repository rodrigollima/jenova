from flask.ext.restful import abort
from jenova.resources.base import BaseResource, abort_if_obj_doesnt_exist
from jenova.components.zimbra import ZimbraReport
from jenova.models import (
  Reseller, Client, DomainSchema, Domain
)

class ResellerReportResource(BaseResource):
  def __init__(self):
    filters = ['id', 'name']
    super(ResellerReportResource, self).__init__(filters)
    

  def get(self, target_reseller):
    self.parser.add_argument('export', type=bool, location='args')
    reqdata = self.parser.parse_args()

    export = reqdata.get('export') or False

    reseller = abort_if_obj_doesnt_exist(self.filter_by, target_reseller, Reseller)

    clients = Client.query.join(Reseller, Client.reseller_id == Reseller.id) \
        .filter(Reseller.name == target_reseller) \
        .all()
    domains = Domain.query\
    .filter(Reseller.id == Client.reseller_id)\
    .filter(Domain.client_id == Client.id)\
    .filter(Reseller.id == reseller.id)\
    .all()

    # r = {
    #   'reseller' : {
    #     'name' : '',
    #     'bep' : '',
    #     'std' : '',
    #     'pro' : '',
    #     'mxLX' : '',
    #     'mxPX' : '',
    #     'n_clients' : '',
    #     'n_domains' : '',
    #     'clients' : [{
    #       'name' : '',
    #       'bep' : '',
    #       'std' : '',
    #       'pro' : '',
    #       'mxLX' : '',
    #       'mxPX' : '',
    #       'n_domains' : '',
    #       'domains' : [{
    #         'name' : '',
    #         'services' : '',
    #         'bep' : '',
    #         'std' : '',
    #         'pro' : '',
    #         ''
    #       }]
    #     }]
    #   }
    # }
    
    res = []
    
    r_reseller = {
      'name' : reseller.name,
      'bep' : 0,
      'std' : 0,
      'pro' : 0,
      'n_clients' : 0,
      'n_domains' : 0,
      'domains' : []
    }
    
    d_list = []
    for domain in domains:
      r_reseller['n_domains'] += 1
      d_list.append(domain.name)
      
    res.append(r_reseller)

    return {
      'response' : res
    }
