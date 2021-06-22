import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIOSD(object):
    def __init__(self, **api_details):
        self.fsid = api_details["fsid"]
        self.base_api = "cluster/"
        self.api = None
        self.commands = ["scrub", "deep_scrub", "repair"]

    def construct_api(self):
        self.api = self.base_api + self.fsid + "/" + "osd"
        log.debug(self.api)
        return self.api


class APIOSDOps(APIOSD):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIOSDOps, self).__init__(**kwargs)
        self.json_osd = None

    def osd_config(self):

        api = self.base_api + self.fsid + "/osd_config"
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_osd = json.loads(pretty_response)

    def get_osd(self):

        log.info("api osd command")
        api = self.construct_api()
        log.info(api)
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_osd = json.loads(pretty_response)

        log.debug("api with command")
        api = self.construct_api() + "/command"
        log.debug(api)
        response2 = self.auth.request("GET", api, verify=False)
        response2.raise_for_status()
        pretty_response2 = json.dumps(response2.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response2)

    def get_osd_id(self):

        log.debug("api testing with osd id")
        log.debug("****************************************")

        # print self.json_osd

        for each_id in self.json_osd:

            # print 'got osd id %s' % each_id['id']

            # get osd_api_id
            api = self.construct_api() + "/" + str(each_id["id"])
            log.debug("osd with id %s" % str(each_id["id"]))
            log.debug("api: %s" % api)

            response = self.auth.request("GET", api, verify=False)
            response.raise_for_status()
            log.debug("response: \n %s" % response.json())

            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response \n %s" % pretty_response)

    def get_osd_id_with_command(self):

        log.debug("api testing with osd id and command")
        log.debug("****************************************")

        for each_id in self.json_osd:

            for each_commmand in self.commands:

                # print 'got osd id: %s ' % each_id['id']

                api = self.construct_api() + "/" + str(each_id["id"]) + "/" + "command"
                log.debug("api: %s" % api)

                response = self.auth.request("GET", api, verify=False)
                response.raise_for_status()
                log.debug("response: \n %s" % response.json())

                pretty_response = json.dumps(response.json(), indent=2)
                log.debug("pretty json response \n %s" % pretty_response)

                with_command_api = api + "/" + each_commmand
                log.debug("osd with command %s" % each_commmand)
                log.debug("api: %s" % with_command_api)

                response2 = self.auth.request("GET", with_command_api, verify=False)
                response2.raise_for_status()
                log.debug("response: \n %s" % response2.json())

                pretty_response2 = json.dumps(response2.json(), indent=2)
                log.debug("pretty json response \n %s" % pretty_response2)

    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(15, "test OSD API")
    add_test_info.started_info()

    try:

        api_osd_ops = APIOSDOps(**config_data)
        api_osd_ops.osd_config()
        api_osd_ops.get_osd()
        api_osd_ops.get_osd_id()
        api_osd_ops.get_osd_id_with_command()

        add_test_info.status("ok")

    except Exception, e:
        log.error("test error")
        log.error(e)
        add_test_info.status("error")

    add_test_info.completed_info()


if __name__ == "__main__":
    config_data = config.get_config()

    if not config_data["auth"]:
        log.error("auth failed")

    else:
        exec_test(config_data)
