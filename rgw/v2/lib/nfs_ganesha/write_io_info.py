import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.utils.utils import FileOps

log = logging.getLogger()

IO_INFO_FNAME = "io_info.yaml"


class BasicIOInfoStructure(object):
    def __init__(self):
        self.initial = lambda: {"users": list()}

        self.user = lambda **args: {
            "user_id": args["user_id"],
            "access_key": args["access_key"],
            "secret_key": args["secret_key"],
            "io": list(),
        }

        self.io = lambda **args: {
            "name": args["name"],
            "type": args["type"],
            "s3_convention": args["s3_convention"],
            "md5": args["md5"],
            "test_properties": list(),
        }


class ExtraIOInfoStructure(object):
    def __init__(self):

        self.op_code = lambda op_code: {"op_code": op_code}
        self.version_count = lambda version_count: {"version_count": version_count}


# class to add io info to yaml file


class AddIOInfo(object):
    def __init__(self, yaml_fname=IO_INFO_FNAME):

        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type="yaml")


class IOInfoInitialize(AddIOInfo):
    def __init__(self):

        super(IOInfoInitialize, self).__init__()

    def initialize(self, data):

        log.info("initial_data: %s" % (data))

        self.file_op.add_data(data)


class AddUserInfo(AddIOInfo):
    """
    This class is used to add the user information to the yaml
    The functions in this class are
    1. add_user_info()

    """

    def __init__(self):

        super(AddUserInfo, self).__init__()

    def add_user_info(self, user):
        """
        Function to add the user information to the yaml

        Parameters:
            user: user details

        Returns:

        """

        log.info("got user info structure: %s" % user)

        yaml_data = self.file_op.get_data()

        log.info("got yaml data %s" % yaml_data)

        yaml_data["users"].append(user)

        log.info("data to add: %s" % yaml_data)

        self.file_op.add_data(yaml_data)


class IOInfo(AddIOInfo):
    """
    This class is add IO information to the yaml
    The functions in this class are
    1. add_io_info()
    2. add_properties()
    """

    def __init__(self):
        super(IOInfo, self).__init__()

    def add_io_info(self, access_key, io_info):
        """
        Function to add user and access key information on IO

        Parameters:
            access_key(char):
            io_info:

        Return:

        """
        yaml_data = self.file_op.get_data()

        indx = None

        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                indx = i
                break

        yaml_data["users"][indx]["io"].append(io_info)

        self.file_op.add_data(yaml_data)

    def add_properties(self, access_key, io_name, properties):
        """
        Function to add properties

        Parameters:
            access_key(char):
            io_name(char):
            properties(char):
        """
        yaml_data = self.file_op.get_data()

        access_key_indx = None
        io_indx = None

        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break

        for i, k in enumerate(yaml_data["users"][access_key_indx]["io"]):

            if k["name"] == io_name:
                io_indx = i
                break

        yaml_data["users"][access_key_indx]["io"][io_indx]["properties"].append(
            properties
        )

        self.file_op.add_data(yaml_data)
