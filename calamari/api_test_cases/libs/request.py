from utils.utils import validate_http


class APIRequest(object):
    def __init__(self, http_request):
        self.http_request = http_request
        self.api = http_request.base_url + 'cluster/' + http_request.fsid + '/' + 'request'
        self.api2 = http_request.base_url + 'request/'

    def check_state(self, request_id):
        api = self.api2 + request_id
        response = self.http_request.get(api)
        content = validate_http(response)
        return content

    def check_completed(self, request_id):
        api = self.api2 + request_id + '?state=complete'
        response = self.http_request.get(api)
        content = validate_http(response)
        return content

    def check_submitted(self, request_id):
        api = self.api2 + request_id + '?state=submitted'
        response = self.http_request.get(api)
        content = validate_http(response)
        return content

    def cancel_request(self, request_id):
        api = self.api2 + request_id + '/cancel'
        response = self.http_request.post(api)
        content = validate_http(response)
        return content



