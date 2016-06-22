import libs.log as log
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from utils.utils import check_request_id
from libs.request import APIRequest
import traceback
import json
from config import MakeMachines


class Test(object):

    def __init__(self, **config):

        self.http_request = HTTPRequest(config['ip'], config['port'], config['username'], config['password'])

        assert self.http_request.login(), "login failed"

        assert self.http_request.getfsid(), "failed to get fsid"

        self.api_request = APIRequest(self.http_request)

        self.osd_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/osd"

    def get_osds(self):


        try:

            # api/v2/cluster/<fsid>/osd  : GET

            url = self.osd_url

            response = self.http_request.get(url)
            log.info(response.content)

            response.raise_for_status()

            pretty_response = json.dumps(response.json(), indent=2)
            osds = json.loads(pretty_response)

            self.osds = osds

            self.osd_ids = [ids['id'] for ids in self.osds]

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def edit_osd(self, data):

        # api/v2/cluster/<fsid>/osd/<osd_id>  PATCH

        log.info('-------------started editing osd ')

        try:

            for id in self.osd_ids:

                url = self.osd_url + "/" + str(id)

                log.info('data to patch: \n%s' %data )

                response = self.http_request.patch(url, data)

                log.info(response.content)

                response.raise_for_status()

                pretty_response = json.dumps(response.json(), indent=2)
                cleaned_response = json.loads(pretty_response)

                patched = check_request_id(self.api_request, cleaned_response['request_id'])

                if patched:
                    log.info('patched')

            self.get_osds()

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def get_commands(self):

        # api/v2/cluster/<fsid>/osd/command  : GET

        try:
            url = self.osd_url + "/command"

            response = self.http_request.get(url)

            log.info(response.content)
            response.raise_for_status()

            # pretty_response = json.dumps(response.json(), indent=2)
            # osd_commands = json.loads(pretty_response)

            self.osd_commands = response.content

            self.osd_commands = self.osd_commands.replace('[', '').replace(']', '').replace('"', '').split(',')

            self.osd_commands = [x.replace(' ', '') for x in self.osd_commands]

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def get_osd_command(self):

        # api/v2/cluster/<fsid>/osd/<osd_id>/command

        try:

            for id in self.osd_ids:

                url = self.osd_url +  "/" + str(id) + "/command"

                response = self.http_request.get(url)

                log.info(response.content)
                response.raise_for_status()

                pretty_response = json.dumps(response.json(), indent=2)
                osd_id_commands = json.loads(pretty_response)

                log.info(osd_id_commands)

        except Exception:
            log.error('\n%s' % traceback.format_exc())
            raise AssertionError

    def post_commands_to_osd(self):

        # api/v2/cluster/<fsid>/osd/<osd_id>/command/<command>

        try:

            for id in self.osd_ids:

                url = self.osd_url + "/" + str(id) + "/command"

                print 'osd_commands %s ' % self.osd_commands

                for command in self.osd_commands:

                    print 'command to append url %s' % command

                    url2 = url + "/" + command

                    data = {'verify': False}

                    response = self.http_request.post(url2, data)
                    log.info(response.content)

                    response.raise_for_status()

                    pretty_response = json.dumps(response.json(), indent=2)
                    cleaned_reponse = json.loads(pretty_response)

                    command_exec = check_request_id(self.api_request, cleaned_reponse['request_id'])

                    if command_exec:
                        log.info('command executed')

        except Exception:

            log.error('\n%s' % traceback.format_exc())
            raise AssertionError


def exec_test(config_data):

    add_test_info = AddTestInfo(9, '\naapi/v2/cluster/<fsid>/osd \n'
                                   'api/v2/cluster/<fsid>/osd/<osd_id> \n'
                                   'api/v2/cluster/<fsid>/osd /command \n'
                                   'api/v2/cluster/<fsid>/osd/<osd_id>/command \n'
                                   'api/v2/cluster/<fsid>/osd/<osd_id>/command/<command>  \n')
    add_test_info.started_info()

    try:
        osd_ops = Test(**config_data)

        osd_ops.get_osds()

        data = {'up': False}

        osd_ops.edit_osd(data)

        data = {'up': True}

        osd_ops.edit_osd(data)

        # part 1 ends

        # osd_ops.get_commands()
        # osd_ops.get_osd_command()
        # osd_ops.post_commands_to_osd()

        # part 2 ends

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
