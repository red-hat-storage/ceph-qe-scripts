import requests
import log
import json
import socket


class AuthenticateClient(object):

    def __init__(self, http, ip, port, username, password):
        requests.packages.urllib3.disable_warnings()
        self.client = requests.session()
        self.base_url = '%s://%s:%s/api/v2/' % (http, socket.gethostbyname(socket.getfqdn()), port)
        self.token = None
        self.headers = None
        self.fsid = None

        self.username = username
        self.password = password

    def getfsid(self):

        try:

            url = self.base_url + 'cluster'

            response = self.client.get(url, verify=False)

            response.raise_for_status()

            log.info(response.content)

            pretty_cluster_details = json.dumps(response.json(), indent=2)
            pretty_cluster_json = json.loads(pretty_cluster_details)[0]

            self.fsid = pretty_cluster_json['id']

            return True
        except Exception, e:
            log.error(e)
            return False

    def login(self):

        try:
            url = self.base_url + 'auth/login/'

            log.info('login_url: %s' % url)

            login_data = {'username': self.username, 'password': self.password, 'next': '/'}
            response = self.client.post(url, login_data, verify=False)

            response.raise_for_status()

            self.token = response.cookies['XSRF-TOKEN']
            self.headers = {'X-XSRF-TOKEN': self.token}

            return True

        except Exception, e:
            log.error(e)
            return False

    def logout(self):

            try:
                url = self.base_url + 'auth/logout'
                self.headers['Referer'] = url

                log.info('logout_url: %s' % url)

                response = self.client.post(url, verify=False, headers=dict(self.headers))

                response.raise_for_status()

                return True

            except Exception, e:
                log.error(e)
                return False


class HTTPRequest(AuthenticateClient):

    def __init__(self, http, ip, port, username, password):
        super(HTTPRequest, self).__init__(http, ip, port, username, password)

    def get(self, url):

        log.info('url to get: %s' % url)

        response = self.client.get(url, verify=False)

        return response

    def post(self, url, data):

        log.info('url to post: %s' % url)

        self.headers['Referer'] = url

        response = self.client.post(url, data=data, verify=False,
                                    headers=self.headers)

        return response

    def patch(self, url, data):

        log.info('url to patch: %s' % url)

        self.headers['Referer'] = url

        response = self.client.patch(url, data, verify=False,
                                     headers=self.headers)

        return response

    def delete(self, url):

        log.info('url to delete: %s' % url)

        self.headers['Referer'] = url

        response = self.client.delete(url, verify=False,
                                      headers=self.headers)

        return response



