import utils.log as log
from utils.utils import pretty_ressponse, validate_http


class Request(object):
    def __init__(self, **kwargs):
        self.fsid = kwargs['fsid']
        self.auth = kwargs['auth']
        self.api = 'cluster/' + self.fsid + '/' + 'request'
        self.api2 = 'request/'

    def check_state(self, request_id):
        api = self.api2 + request_id
        response = self.auth.request('GET', api)
        content = validate_http(response)
        return content

    def check_completed(self, request_id):
        api = self.api2 + request_id + '?state=complete'
        response = self.auth.request('GET', api)
        content = validate_http(response)
        return content

    def check_submitted(self, request_id):
        api = self.api2 + request_id + '?state=submitted'
        response = self.auth.request('GET', api)
        content = validate_http(response)
        return content

    def cancel_request(self, request_id):
        api = self.api2 + request_id + '/cancel'
        response = self.auth.post(api)
        content = validate_http(response)
        return content



