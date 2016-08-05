from flask.ext.restful import abort
from jenova.resources.base import BaseResource, abort_if_obj_doesnt_exist
from jenova.models import (
  Client, Domain, DomainSchema, Reseller
)


class ReportServiceReseller(BaseResource):
  def __init__(self):
    filters = ['name']
    super(ReportServiceReseller, self).__init__(filters)

  def get(self, reseller_name, service_name, domain_name=''):
    reseller = abort_if_obj_doesnt_exist(self.filter_by, reseller_name, Reseller)
    service = abort_if_obj_doesnt_exist('name', service_name, Service)

    # TODO
    # self.parser.add_argument('limit', type=int, location='args')
    # self.parser.add_argument('offset', type=int, location='args')
    # reqdata = self.parser.parse_args()
    # offset, limit = reqdata.get('offset') or 0, reqdata.get('limit') or 100
    
    if domain_name:
      domains = Domain.query\
        .filter(Reseller.id == Client.reseller_id)\
        .filter(Domain.client_id == Client.id)\
        .filter(Reseller.id == reseller.id)\
        .filter(Domain.name == domain_name)\
        .one()
    else:
      domains = Domain.query\
        .filter(Reseller.id == Client.reseller_id)\
        .filter(Domain.client_id == Client.id)\
        .filter(Reseller.id == reseller.id)\
        .all()

  
    return {
      'response' : {
        'domains' : DomainSchema(many=True).dump(domains).data,
      }
    }, 200