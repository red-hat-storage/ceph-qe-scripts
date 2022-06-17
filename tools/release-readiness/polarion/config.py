import yaml


class Config:
    """
    Module for reading all configuration information from config/config.yaml file.
    Make sure the config.yaml file exists and all the relevant fields are populated.
    """

    def __init__(self):
        self.project_id = None
        self.file_name = None
        self.key = None
        self.tags = None

        self.GS_CREDENTIALS = None
        self.data = None
        self.color = None
        self.color_charts = None
        self.polarion_report_summary = None
        self.colors_for_summary = None
        self.sender_user = None
        self.recipient_user = None
        self.url = None
        self.component_filter = None
        self.comp_color = None

    def load(self):
        """Function loads the configuration information."""
        with open(r"config/config.yml", "r") as file:
            yaml_config = yaml.safe_load(file)
        self.project_id = yaml_config["project_id"]
        self.file_name = yaml_config["file_name"]
        self.key = yaml_config["key"]
        self.tags = yaml_config["tags"]

        self.data = yaml_config["data"]
        self.color = yaml_config["colors"]
        self.color_charts = yaml_config["color_charts"]
        self.GS_CREDENTIALS = yaml_config["GS_CREDENTIALS"]
        self.sender_user = yaml_config["sender_user"]
        self.recipient_user = yaml_config["recipient_user"]
        self.url = yaml_config["url"]
        self.component_filter = yaml_config["component_filter"]
        self.comp_color = yaml_config["comp_colors"]

    def view(self):
        """Function to display googlesheet creds."""
        print(self.GS_CREDENTIALS)
