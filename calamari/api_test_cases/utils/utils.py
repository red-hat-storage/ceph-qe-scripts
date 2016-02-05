import log
import json
import time


class Machines(object):
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname

    def ip(self):
        return self.ip

    def hostname(self):
        return self.hostname


def pretty_ressponse(response):

    pretty_response = json.dumps(response.json(),indent=2)

    log.debug('pretty json response from  api\n%s' % pretty_response)

    json_data = json.loads(pretty_response)
    return json_data


def validate_http(response):

    data = False

    try:
        response.raise_for_status()
        data = pretty_ressponse(response)

    except Exception, e:
        log.debug(e)

    return data


def check_request_id(request, request_id):

    status = request.check_completed(request_id)

    # asserts is status['error'] is true
    assert status['error'] != "true", status['error_message']

    log.debug('checking the state %s' % status['state'])

    if status['state'] == 'complete':
        log.debug('action complete')
        return True
    else:
        time.sleep(10)
        log.debug('entered recursive mode')
        check_request_id(request, request_id)


