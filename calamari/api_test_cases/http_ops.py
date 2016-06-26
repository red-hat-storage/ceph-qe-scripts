import libs.log as log
from libs.http_client import HTTPRequest
from libs.request import APIRequest
import traceback
from utils.utils import check_request_id, clean_response


class Initialize(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['http'], config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

    def get(self, url):

        try:

            response = self.http_request.get(url)

            cleaned_response = clean_response(response)

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def post(self, url, data, request_api=True):

        try:

            log.info('data to post:\n%s' % data)

            response = self.http_request.post(url, data)

            cleaned_response = clean_response(response)

            if request_api:

                check_request_id(self.api_request, cleaned_response['request_id'])

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def patch(self, url, data, request_api=True):

        try:

            log.info('data to patch\n %s' % data)

            response = self.http_request.patch(url, data)

            cleaned_response = clean_response(response)

            if request_api:
                check_request_id(self.api_request, cleaned_response['request_id'])

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def delete(self, url, request_api=True):

        try:

            response = self.http_request.delete(url)

            cleaned_response = clean_response(response)

            if request_api:
                check_request_id(self.api_request, cleaned_response['request_id'])

            return cleaned_response

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError
