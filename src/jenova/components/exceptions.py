class JenovaError(Exception): pass
class TaskError(Exception): pass
class JwtInconsistentDataError(JenovaError): pass
class TaskZimbraInconsistencyError(TaskError): pass
class DnsError(JenovaError):
  def __init__(self, message, response=None, status_code = 400):
    """ Request Errors from PowerDns system
    :param message: Error message
    :param response: PowerDns Errors in dict format. Ref: https://doc.powerdns.com/md/httpapi/api_spec/#errors
    """
    self.message = message
    self.response = response
    self.status_code = status_code

    super(DnsError, self).__init__(message)

class mxheroError(JenovaError):
  def __init__(self, message, response=None):
    """ Request Errors from mxhero api
    :param message: Error message
    :param response: mxhero Errors in dict format. 
    """
    self.message = message
    self.response = response

    super(mxheroError, self).__init__(message)