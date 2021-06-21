import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIRequest(object):
    def __init__(self, **api_details):
        self.fsid = api_details["fsid"]
        self.api = None

    def construct_api_non_clusterId(self):
        api = "request"
        print "in construct api"
        log.debug(api)
        return api

    def construct_api(self):
        api = "cluster/" + self.fsid + "/" + "request"
        log.debug(api)
        return api


class APIRequestOps(APIRequest):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIRequestOps, self).__init__(**kwargs)
        self.json_request = None

    def get_request(self):

        api = self.construct_api()
        log.info("api testing with fsid")
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_request = json.loads(pretty_response)

    def get_request_id(self):

        log.info("api testing with each request id")
        log.debug("****************************************")

        for each_id in self.json_request["results"]:

            api = self.construct_api() + "/" + str(each_id["id"])
            log.debug("pool with id %s" % str(each_id["id"]))
            log.debug("api: %s" % api)

            response = self.auth.request("GET", api, verify=False)
            response.raise_for_status()
            log.debug("response: \n %s" % response.json())

            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response \n %s" % pretty_response)


class APIRequestOpsNoFsid(APIRequest):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIRequestOpsNoFsid, self).__init__(**kwargs)
        self.json_request = None

    def get_request(self):

        api = self.construct_api_non_clusterId()
        log.debug("api_testing without fsid")
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_request = json.loads(pretty_response)

    def get_request_id(self):

        log.info("api testing with each request id / no fsid")
        log.debug("****************************************")

        for each_id in self.json_request["results"]:

            api = "request" + "/" + str(each_id["id"])
            log.debug("request with id %s" % str(each_id["id"]))
            log.debug("api: %s" % api)

            response = self.auth.request("GET", api, verify=False)
            response.raise_for_status()
            log.debug("response: \n %s" % response.json())

            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response \n %s" % pretty_response)

            # request id with states
            states = ["complete", "submitted"]

            log.info("api testing with states")

            for each_state in states:
                api_with_state = api + "?state=" + each_state
                log.debug("request with id %s" % str(each_id["id"]))
                log.debug("api: %s" % api_with_state)

                response2 = self.auth.request("GET", api_with_state, verify=False)
                response2.raise_for_status()
                log.debug("response: \n %s" % response2.json())

                pretty_response2 = json.dumps(response2.json(), indent=2)
                log.debug("pretty json response \n %s" % pretty_response2)


def exec_test(config_data):

    add_test_info = AddTestInfo(10, "API request")
    add_test_info.started_info()

    try:

        api_request = APIRequestOps(**config_data)
        api_request.get_request()
        api_request.get_request_id()

        api_request_no_fsid = APIRequestOpsNoFsid(**config_data)
        api_request_no_fsid.get_request()
        api_request_no_fsid.get_request_id()

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
