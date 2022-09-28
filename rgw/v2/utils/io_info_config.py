class IoInfoConfig:
    _instance = None
    io_info_fname = "io_info.yaml"

    def __new__(
        cls,
        io_info_fname=None,
    ):
        if not IoInfoConfig._instance:
            IoInfoConfig._instance = cls
        if io_info_fname:
            IoInfoConfig._instance.io_info_fname = io_info_fname
        return IoInfoConfig._instance
