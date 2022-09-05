import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.utils.utils import FileOps

log = logging.getLogger()

IO_INFO_FNAME = "io_info.yaml"

EXEC_INFO_STRUCTURE = {
    "obj": None,
    "resource": None,
    "kwargs": None,
    "args": None,
    "extra_info": None,
}


class BasicIOInfoStructure(object):
    """
    This class defines the basic IO structure for the yaml.
    """

    def __init__(self):
        """
        Initializes the variables
        """
        self.initial = lambda: {"users": list()}
        self.user = lambda **args: {
            "user_id": args["user_id"],
            "access_key": args["access_key"],
            "secret_key": args["secret_key"],
            "bucket": list(),
            "deleted": False,
        }
        self.bucket = lambda **args: {
            "name": args["name"],
            "properties": list(),
            "keys": list(),
            "curr_versioning_status": "disabled",
            "deleted": False,
        }
        self.key = lambda **args: {
            "name": args["name"],
            "size": args["size"],
            "md5_local": args["md5_local"],
            "upload_type": args["upload_type"],
            "properties": list(),
            "versioning_info": list(),
            "deleted": False,
        }
        self.version_info = lambda **args: {
            "version_id": args["version_id"],
            "md5_local": args["md5_local"],
            "count_no": args["count_no"],
            "size": args["size"],
            "deleted": False,
        }


class ExtraIOInfoStructure(object):
    """
    This class provides extra information such as current versioning status, version code, op code
    """

    def __init__(self):
        self.op_code = lambda op_code: {"op_code": op_code}
        self.version_count = lambda version_count: {"version_count": version_count}
        self.curr_versioning_status = lambda curr_versioning_status: {
            "curr_versioning_status": curr_versioning_status
        }


class TenantInfo(object):
    """
    This class provides information on tenant
    """

    def __init__(self):
        self.tenant = lambda tenant: {"tenant": tenant}


class AddIOInfo(object):
    """
    This class creates yaml with fname provided
    """

    def __init__(self, yaml_fname=IO_INFO_FNAME):
        self.yaml_fname = yaml_fname
        self.file_op = FileOps(self.yaml_fname, type="yaml")


class IOInfoInitialize(AddIOInfo):
    """
    This class initializes data.
    The functions here are
    1. initialize(): Initialize data
    """

    def __init__(self):
        super(IOInfoInitialize, self).__init__()

    def initialize(self, data):
        """
        This function is to initialize data
        Parameter:
            data
        """
        log.info("initial_data: %s" % (data))
        self.file_op.add_data(data)


class AddUserInfo(AddIOInfo):
    """
    This class is to add the user information to the yaml
    The function/s in this class are
    1. add_user_info() : Add the user information to the yaml
    """

    def __init__(self):
        super(AddUserInfo, self).__init__()

    def add_user_info(self, user):
        """
        This function is to add the user information to the yaml
        Parameters:
            user:
        """
        log.info("got user info structure: %s" % user)
        yaml_data = self.file_op.get_data()
        log.info("got yaml data %s" % yaml_data)
        yaml_data["users"].append(user)
        log.info("data to add: %s" % yaml_data)
        self.file_op.add_data(yaml_data)

    def set_user_deleted(self, access_key):
        """
        This function is to add the user information to the yaml
        Parameters:
            access_key:
        """
        log.info("Setting user as deleted")
        yaml_data = self.file_op.get_data()
        indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                indx = i
                break
        yaml_data["users"][indx]["deleted"] = True
        self.file_op.add_data(yaml_data)


class BucketIoInfo(AddIOInfo):
    """
    This class is to add bucket information to the yaml.
    The function/s in this class are
    1. add_bucket_info()
    2. add_versioning_status()
    3. add_properties()
    """

    def __init__(self):
        super(BucketIoInfo, self).__init__()

    def add_bucket_info(self, access_key, bucket_info):
        """
        This function is to add bucket information to the yaml
        Parameters:
            access_key:
            bucket_info:
        """
        yaml_data = self.file_op.get_data()
        indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                indx = i
                break
        yaml_data["users"][indx]["bucket"].append(bucket_info)
        self.file_op.add_data(yaml_data)

    def set_bucket_deleted(self, bucket_name):
        """
        This function is to add bucket information to the yaml
        Parameters:
            access_key:
            bucket_name:
        """
        log.info(f"marking bucket '{bucket_name}' as deleted")
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        for i, _ in enumerate(yaml_data["users"]):
            for j, k in enumerate(yaml_data["users"][i]["bucket"]):
                if k["name"] == bucket_name:
                    bucket_indx = j
                    access_key_indx = i
                    break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["deleted"] = True
        self.file_op.add_data(yaml_data)

    def add_versioning_status(self, access_key, bucket_name, versioning_status):
        """
        This function is add versioning information to the yaml
        Parameters:
            access_key:
            bucket_name:
            versioning_status:
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx][
            "curr_versioning_status"
        ] = versioning_status
        self.file_op.add_data(yaml_data)

    def add_properties(self, access_key, bucket_name, properties):
        """
        This function is to add propertirs to the yaml
        Parameters:
            access_key:
            bucket_name:
            properties:
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["properties"].append(
            properties
        )
        self.file_op.add_data(yaml_data)


class KeyIoInfo(AddIOInfo):
    """
    This class is to provide key information
    """

    def __init__(self):
        super(KeyIoInfo, self).__init__()

    def add_keys_info(self, access_key, bucket_name, key_info):
        """
        This function is to add key information to the yaml.

        Parameters:
            access_key: access key
            bucket_name: Name of the bucket
            key_info: key information
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"].append(
            key_info
        )
        self.file_op.add_data(yaml_data)

    def set_key_deleted(self, bucket_name, key_name):
        """
        This function to add properties to the yaml

        Parameters:
            bucket_name: name of the bucket
            key_name: name of the key
        """
        log.info(f"marking key '{key_name}' in bucket '{bucket_name}' as deleted")
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        key_indx = None
        for i, _ in enumerate(yaml_data["users"]):
            for j, k in enumerate(yaml_data["users"][i]["bucket"]):
                if k["name"] == bucket_name:
                    bucket_indx = j
                    access_key_indx = i
                    break
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"]
        ):
            if k["name"] == key_name:
                key_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][key_indx][
            "deleted"
        ] = True
        self.file_op.add_data(yaml_data)

    def set_keys_deleted_in_bucket_with_prefix(
        self, access_key, bucket_name, prefix_list
    ):
        """
        This function to add properties to the yaml

        Parameters:
            access_key: access key
            bucket_name: name of the bucket
            prefix_list: list of pefixes
        """
        log.info(
            f"marking keys in bucket '{bucket_name}' as deleted with prefix in {prefix_list}"
        )
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"]
        ):
            for prefix in prefix_list:
                if k["name"].startswith(prefix):
                    yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][
                        i
                    ]["deleted"] = True
        self.file_op.add_data(yaml_data)

    def add_properties(self, access_key, bucket_name, key_name, properties):
        """
        This function to add properties to the yaml

        Parameters:
            access_key: access key
            bucket_name: name of the bucket
            key_name: name of the key
            properties: properties
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        key_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"]
        ):
            if k["name"] == key_name:
                key_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][key_indx][
            "properties"
        ].append(properties)
        self.file_op.add_data(yaml_data)

    def add_versioning_info(self, access_key, bucket_name, key_name, versioning_info):
        """
        This function is to add versioning information to the yaml

        Parameters:
            access_key: access key
            bucket_name: name of the bucket
            key_name: name of the key
            versioning_info: versioning information
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        key_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"]
        ):
            if k["name"] == key_name:
                key_indx = i
                break
        yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][key_indx][
            "versioning_info"
        ].append(versioning_info)
        self.file_op.add_data(yaml_data)

    def delete_version_info(self, access_key, bucket_name, key_name, version_id):
        """
        This function is remove the versioning information from the yaml

        Parameters:
            access_key:  access key
            bucket_name: name of the bucket
            key_name: name of the key
            version_id: version id of the object
        """
        yaml_data = self.file_op.get_data()
        access_key_indx = None
        bucket_indx = None
        key_indx = None
        version_info_indx = None
        for i, k in enumerate(yaml_data["users"]):
            if k["access_key"] == access_key:
                access_key_indx = i
                break
        for i, k in enumerate(yaml_data["users"][access_key_indx]["bucket"]):
            if k["name"] == bucket_name:
                bucket_indx = i
                break
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"]
        ):
            if k["name"] == key_name:
                key_indx = i
                break
        # print 'versioing info'
        # print yaml_data['users'][access_key_indx]['bucket'][bucket_indx]['keys'][key_indx]['versioning_info']
        for i, k in enumerate(
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][
                key_indx
            ]["versioning_info"]
        ):
            if k["version_id"] == version_id:
                version_info_indx = i
                break
            yaml_data["users"][access_key_indx]["bucket"][bucket_indx]["keys"][
                key_indx
            ]["versioning_info"].pop(version_info_indx)
        self.file_op.add_data(yaml_data)


def logioinfo(func):
    """
    This function is to add IO information
    """

    def write(exec_info):
        """
        This function is to add bucket and object Io information

        Parameters:
            exec_info

        Returns:
            write
        """
        log.info("in write")
        log.info(exec_info)
        ret_val = func(exec_info)
        if ret_val is False:
            return ret_val
        gen_basic_io_info_structure = BasicIOInfoStructure()
        gen_extra_io_info_structure = ExtraIOInfoStructure()
        write_bucket_info = BucketIoInfo()
        write_key_info = KeyIoInfo()
        obj = exec_info["obj"]
        resource_name = exec_info["resource"]
        extra_info = exec_info.get("extra_info", None)
        log.info("obj_name :%s" % obj)
        log.info("resource_name: %s" % resource_name)
        if "s3.Bucket" == type(obj).__name__:
            log.info("in s3.Bucket logging")
            resource_names = ["create"]
            if resource_name in resource_names:
                access_key = extra_info["access_key"]
                log.info("adding io info of create bucket")
                bucket_info = gen_basic_io_info_structure.bucket(**{"name": obj.name})
                write_bucket_info.add_bucket_info(access_key, bucket_info)
        if "s3.Object" == type(obj).__name__:
            log.info("in s3.Object logging")
            resource_names = ["upload_file", "initiate_multipart_upload"]
            if resource_name in resource_names:
                log.info(
                    "writing log for upload_type: %s"
                    % extra_info.get("upload_type", "normal")
                )
                access_key = extra_info["access_key"]
                # setting default versioning status to disabled
                extra_info["versioning_status"] = extra_info.get(
                    "versioning_status", "disabled"
                )
                log.info("versioning_status: %s" % extra_info["versioning_status"])
                if (
                    extra_info.get("versioning_status") == "disabled"
                    or extra_info.get("versioning_status") == "suspended"
                ):
                    log.info("adding io info of upload objects")
                    key_upload_info = gen_basic_io_info_structure.key(
                        **{
                            "name": extra_info["name"],
                            "size": extra_info["size"],
                            "md5_local": extra_info["md5"],
                            "upload_type": extra_info.get("upload_type", "normal"),
                        }
                    )
                    write_key_info.add_keys_info(
                        access_key, obj.bucket_name, key_upload_info
                    )
                if extra_info.get("versioning_status") == "enabled":
                    if extra_info.get("version_count_no") == 0:
                        log.info(
                            "adding key io info of upload objects (version enabled)"
                        )
                        key_upload_info = gen_basic_io_info_structure.key(
                            **{
                                "name": extra_info["name"],
                                "size": None,
                                "md5_local": None,
                                "upload_type": extra_info.get("upload_type", "normal"),
                            }
                        )
                        write_key_info.add_keys_info(
                            access_key, obj.bucket_name, key_upload_info
                        )
                    log.info(
                        "adding key version io info of upload objects (version enabled)"
                    )
                    version_upload_info = gen_basic_io_info_structure.version_info(
                        **{
                            "version_id": obj.version_id,
                            "md5_local": extra_info["md5"],
                            "count_no": extra_info["version_count_no"],
                            "size": extra_info["size"],
                        }
                    )
                    log.info("key_version_info: %s" % version_upload_info)
                    write_key_info.add_versioning_info(
                        access_key, obj.bucket_name, obj.key, version_upload_info
                    )
        log.debug("writing log for %s" % resource_name)
        return ret_val

    return write


"""
if __name__ == '__main__':
    # test data

    user_data1 = {'user_id': 'batman',
                  'access_key': '235sff34',
                  'secret_key': '87324skfs',
                  }

    user_data2 = {'user_id': 'heman',
                  'access_key': 'sfssf',
                  'secret_key': '87324skfs',
                  }

    user_data3 = {'user_id': 'antman',
                  'access_key': 'fwg435',
                  'secret_key': '87324skfs',
                  }

    key_info1 = {'name': 'k1', 'size': 374, 'md5_local': 'sfsf734', 'upload_type': 'normal', 'test_op_code': 'create'}
    key_info2 = {'name': 'k2', 'size': 242, 'md5_local': 'sgg345', 'upload_type': 'normal', 'test_op_code': 'create'}
    key_info3 = {'name': 'k3', 'size': 3563, 'md5_local': 'sfy4hfd', 'upload_type': 'normal', 'test_op_code': 'create'}

    key_info4 = {'key_name': 'k4', 'size': 2342, 'md5_local': 'sfsf3534', 'upload_type': 'normal',
                 'test_op_code': 'create', }
    
    key1_version_info1 = {'version_id': 'v1',
                          'md5': 'md51'
                          'size' 'size1'}

    key1_version_info2 = {'version_id': 'v2',
                          'md5': 'md52'
                          'size' 'size2'}

    key1_version_info3 = {'version_id': 'v3',
                          'md5': 'md53'
                          'size' 'size3'}

    # import BasicIOInfoStructure, ExtraIOInfoStructure

    basic_io_struct = BasicIOInfoStructure()
    extened_io_struct = ExtraIOInfoStructure()

    io_init = IOInfoInitialize()

    write_user_info = AddUserInfo()
    write_bucket_io_info = BucketIoInfo()
    write_key_io_info = KeyIoInfo()

    io_init.initialize(basic_io_struct.initial())

    # generate io the structure

    u1 = basic_io_struct.user(**user_data1)
    b1 = basic_io_struct.bucket(**{'name': 'b3', 'test_op_code': 'create'})

    # b1 = dict(b1, **extened_io_struct.version_count('5'))
    # b1 = dict(b1, **extened_io_struct.curr_versioning_status('disabled'))

    k1 = basic_io_struct.key(**key_info1)

    # write the io structure to yaml file

    write_user_info.add_user_info(u1)
    write_bucket_io_info.add_bucket_info(access_key='235sff34', bucket_info=b1)
    write_key_io_info.add_keys_info(access_key='235sff34', bucket_name=b1['name'], key_info=k1)
    write_key_io_info.add_versioning_info(access_key='235sff34', bucket_name=b1['name'], key_name=k1['name'],
                                          versioning_info=key1_version_info1)
    write_key_io_info.add_versioning_info(access_key='235sff34', bucket_name=b1['name'], key_name=k1['name'],
                                          versioning_info=key1_version_info2)

    # io_info.add_keys_info(access_key='235sff34', bucket_name='b3', **key_info3)
    # io_info.add_keys_info(access_key='235sff34', bucket_name='b3', **key_info4)
"""
