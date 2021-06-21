import json

import config
import utils.log as log
from utils.test_desc import AddTestInfo


class APIEvent(object):
    def __init__(self, **api_details):
        self.fsid = api_details["fsid"]
        self.severity = ["INFO", "WARNING", "ERROR", "RECOVERY"]


class APIEventOps(APIEvent):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIEventOps, self).__init__(**kwargs)
        self.json_resp = None

    def construct_event_api(self):
        api = "event"
        log.debug(api)
        return api

    def get_event(self):

        log.info("-----------------------")
        log.info("api event testing")

        api = self.construct_event_api()
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_resp = json.loads(pretty_response)

        for i in self.severity:
            log.info("severity api check with event")
            severity_api = api + "?severity=" + i
            log.debug(severity_api)
            response2 = self.auth.request("GET", severity_api, verify=False)
            response2.raise_for_status()
            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response from  api")
            log.debug(pretty_response)
            self.json_resp = json.loads(pretty_response)


class APIClusterEventOps(APIEvent):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIClusterEventOps, self).__init__(**kwargs)
        self.json_resp = None

    def construct_cluster_event_api(self):
        api = "cluster/" + self.fsid + "/event"
        log.debug(api)
        return api

    def get_cluster_event(self):

        log.info("-----------------------")
        log.info("api event with cluster id testing")

        api = self.construct_cluster_event_api()
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_resp = json.loads(pretty_response)

        for i in self.severity:

            log.info("severity api check, event with cluster")
            severity_api = api + "?severity=" + i
            log.debug(severity_api)
            response2 = self.auth.request("GET", severity_api, verify=False)
            response2.raise_for_status()
            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response from  api")
            log.debug(pretty_response)
            self.json_resp = json.loads(pretty_response)


class APIServerEventOps(APIEvent):
    def __init__(self, **kwargs):
        self.auth = kwargs["auth"]
        super(APIServerEventOps, self).__init__(**kwargs)
        self.json_resp = None

    def construct_server_event_api(self):
        api = "server"
        log.debug(api)
        return api

    def get_server(self):

        api = self.construct_server_event_api()
        response = self.auth.request("GET", api, verify=False)
        response.raise_for_status()
        pretty_response = json.dumps(response.json(), indent=2)
        log.debug("pretty json response from  api")
        log.debug(pretty_response)
        self.json_resp = json.loads(pretty_response)

    def get_server_event_api(self):

        log.info("-----------------------")
        log.info("api event testing")

        log.debug("api testing with each fqdn")
        log.debug("****************************************")

        self.get_server()

        for each_id in self.json_resp:
            api = (
                self.construct_server_event_api()
                + "/"
                + str(each_id["fqdn"])
                + "/event"
            )
            log.debug("event with fqdn %s" % str(each_id["fqdn"]))
            log.debug("api: %s" % api)

            response = self.auth.request("GET", api)
            response.raise_for_status()
            log.debug("response: \n %s" % response.json())

            pretty_response = json.dumps(response.json(), indent=2)
            log.debug("pretty json response \n %s" % pretty_response)

            for i in self.severity:
                log.info("severity api check, event with server")
                severity_api = api + "?severity=" + i
                log.debug(severity_api)
                response2 = self.auth.request("GET", severity_api, verify=False)
                response2.raise_for_status()
                pretty_response = json.dumps(response.json(), indent=2)
                log.debug("pretty json response from  api")
                log.debug(pretty_response)
                self.json_resp = json.loads(pretty_response)

    def put(self):
        pass

    def post(self):
        pass


def exec_test(config_data):

    add_test_info = AddTestInfo(14, "API Event")
    add_test_info.started_info()

    try:

        api_event = APIEventOps(**config_data)
        api_event.get_event()

        api_event_cluster_event = APIClusterEventOps(**config_data)
        api_event_cluster_event.get_cluster_event()

        api_server_event = APIServerEventOps(**config_data)
        api_server_event.get_server_event_api()

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
