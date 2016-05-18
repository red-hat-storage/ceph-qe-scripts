import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
import traceback
import json
from config import MakeMachines
import names


class UserCreationDefination(object):
    def __init__(self):
        pass


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        # assert self.http_request.getfsid(), "failed to get fsid"

        self.user_url = self.http_request.base_url + "user"

        self.users = None

        self.user_ids = None

    def get_users(self):

        try:

            url = self.user_url

            response = self.http_request.get(url)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_content = json.loads(pretty_response)

            self.users = cleaned_content

            self.user_ids = [int(uid['id']) for uid in self.users]

        except Exception:
            log.error('error: \n%s' % traceback.format_exc())
            raise AssertionError

    def create_user(self, data):

        # testing post operation

        try:

            url = self.user_url

            log.debug('definition complete')

            log.debug(data)

            response = self.http_request.post(url, data)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            log.info(cleaned_response)

            return cleaned_response['id']

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def edit_user(self, id, data):

        try:

            url = self.user_url + "/" +str(id)

            response = self.http_request.patch(url, data)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            log.info(cleaned_response)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def delete_user(self, id):

        try:

            url = self.user_url + "/" + str(id)

            response = self.http_request.delete(url)

            response.raise_for_status()

            log.info(response.content)

            pretty_response = json.dumps(response.json(), indent=2)
            cleaned_response = json.loads(pretty_response)

            log.info(cleaned_response)

            # deleted = check_request_id(self.api_request, cleaned_response['request_id'])

            # if deleted:
            #    log.info('deleted')

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(7, '\n api/v2/user \n'
                                   'api/v2/user/<pk>')
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        test.get_users()

        new_user = UserCreationDefination()

        new_user.username = names.get_first_name().lower()
        new_user.email = 'bob@calamari.com'
        new_user.password = 'mybob@1234'

        uid = test.create_user(new_user.__dict__)

        config_data['username'] = new_user.username
        config_data['password'] = new_user.password

        logged_out = test.http_request.logout()

        assert logged_out, "logout failed"

        test2 = Test(**config_data)

        edit = UserCreationDefination()

        edit.email = 'mybob@calamari.com'

        test2.edit_user(uid, edit.__dict__)

        test2.delete_user(uid)

        add_test_info.status('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('test error')

    add_test_info.completed_info()


if __name__ == '__main__':

    machines_config = MakeMachines()

    calamari_config = machines_config.calamari()
    mons = machines_config.mon()
    osds = machines_config.osd()

    exec_test(calamari_config)
