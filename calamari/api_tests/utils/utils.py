import log


class Machines(object):
    def __init__(self, ip, hostname):
        self.ip = ip
        self.hostname = hostname

    def ip(self):
        return self.ip

    def hostname(self):
        return self.hostname


def validate_http(response):

    status_code = response.status_code
    log.info('status_code %s' % status_code)

    if status_code <= 400:
        content = response.json()
        log.info(content)
        return content

    else:
        # here content will not be in json, so no json convertion
        log.error('content %s' % response.content)
        return False
