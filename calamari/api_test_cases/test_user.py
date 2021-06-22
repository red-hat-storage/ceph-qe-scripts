import argparse
import traceback

import libs.log as log
import names
from libs.http_client import HTTPRequest
from utils.test_desc import AddTestInfo
from utils.utils import clean_response, get_calamari_config


class UserCreationDefination(object):
    def __init__(self):
        pass


class Test(HTTPRequest):
    def __init__(self, **config):

        super(Test, self).__init__(
            config["http"],
            config["ip"],
            config["port"],
            config["username"],
            config["password"],
        )

        assert self.login(), "login failed"

        self.user_url = self.base_url + "user"


def exec_test(config_data):

    add_test_info = AddTestInfo(17, "\napi/v2/user\n" "api/v2/user/<pk>")
    add_test_info.started_info()

    try:
        test = Test(**config_data)

        # --------------- get users --------------

        response = test.get(test.user_url)

        clean_response(response)

        # --------------- create new users --------------

        new_user = UserCreationDefination()

        new_user.username = names.get_first_name().lower()
        new_user.email = "bob@calamari.com"
        new_user.password = "mybob@1234"

        log.info("new username: %s" % new_user.username)

        response = test.post(test.user_url, new_user.__dict__)

        new_user_created = clean_response(response)

        new_uid = new_user_created["id"]

        logged_out = test.logout()

        assert logged_out, "logout failed"

        # ------------- edit the user details by logging back as the new user ---------------

        new_config_data = config_data.copy()

        new_config_data["username"] = new_user.username
        new_config_data["password"] = new_user.password

        test2 = Test(**new_config_data)

        edit = UserCreationDefination()

        edit.email = "mybob@calamari.com"

        response = test2.patch(test.user_url + "/" + str(new_uid), edit.__dict__)

        clean_response(response)

        test2.logout()

        # --------------- delete the created user ---------------

        test3 = Test(**config_data)

        response = test3.delete(test3.user_url + "/" + str(new_uid))

        clean_response(response)

        response = test3.get(test2.user_url)

        clean_response(response)

        add_test_info.success("test ok")

    except Exception:
        log.error("\n%s" % traceback.format_exc())
        add_test_info.failed("test error")

    return add_test_info.completed_info(config_data["log_copy_location"])


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Calamari API Automation")

    parser.add_argument(
        "-c",
        dest="config",
        default="config.yaml",
        help="calamari config file: yaml file",
    )

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)
