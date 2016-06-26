import json
import time

from libs import log
import yaml

class Machines(object):
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname

    def ip(self):
        return self.ip

    def hostname(self):
        return self.hostname


def pretty_ressponse(response):

    pretty_response = json.dumps(response.json(), indent=2)

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


def check_request_id(api_request, request_id):

    status = api_request.check_completed(request_id)

    # asserts is status['error'] is true
    assert status['error'] != "true", status['error_message']

    log.debug('checking the state %s' % status['state'])

    if status['state'] == 'complete':
        log.debug('action complete')
        return True
    else:
        time.sleep(10)
        log.debug('entered recursive mode')
        return check_request_id(api_request, request_id)


def clean_response(response):

    log.info(response.content)

    response.raise_for_status()

    pretty_response = json.dumps(response.json(), indent=2)

    cleaned_response = json.loads(pretty_response)

    log.info("\n%s" % pretty_response)

    return cleaned_response


def get_calamari_config(yaml_file):

    with open(yaml_file, 'r') as f:
        doc = yaml.load(f)

    http = doc['calamari']['http']
    ip = doc['calamari']['ip']
    port = doc['calamari']['port']
    username = doc['calamari']['username']
    password = doc['calamari']['password']

    return dict(username=username,
                password=password,
                ip=ip,
                port=port,
                http=http)


