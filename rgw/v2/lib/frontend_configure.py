import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import logging
import time
import traceback
from json import loads

import v2.lib.decorators as decorators
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException
from v2.lib.rgw_config_opts import CephConfOp
from v2.utils.utils import RGWService

SUPPORTED = ["beast", "civetweb"]
log = logging.getLogger()


class RGWSection(object):
    # rgw section in ceph.conf
    def __init__(self):
        self._hostname, self._ip = utils.get_hostname_ip()
        self._ssl_port = 443
        self._non_ssl_port = utils.get_radosgw_port_no()
        self._ceph_conf = CephConfOp()
        self._rgw_service = RGWService()

        # _sections_to_check = ['client.rgw.' + self._hostname,
        #                       'client.rgw.' + self._ip]
        # log.info('checking for existence of sections: {}'.format(_sections_to_check))
        # _sections = [section for section in _sections_to_check if self._ceph_conf.check_if_section_exists(section)]
        #
        # log.info('got section(s): {}'.format(_sections))
        # if not any(_sections):
        #     raise RGWBaseException('No RGW section in ceph.conf')
        # self.section = _sections[0]

        sections_in_ceph_conf = self._ceph_conf.cfg.sections()
        log.info("got sections from ceph_conf: {}".format(sections_in_ceph_conf))
        rgw_section = list(
            filter(lambda section: "rgw" in section, sections_in_ceph_conf)
        )
        if not rgw_section:
            raise RGWBaseException("No RGW section in ceph.conf")
        self.section = rgw_section[0]
        log.info("using section: {}".format(self.section))


class RGWSectionOptions(RGWSection):
    def __init__(self):
        RGWSection.__init__(
            self,
        )
        self.rgw_section_options = dict(self._ceph_conf.cfg.items(self.section))
        log.info("options under {}".format(self.section))
        log.info(self.rgw_section_options)


class Frontend(RGWSectionOptions):
    def __init__(self):
        RGWSectionOptions.__init__(self)

        log.info("checking current rgw frontend")
        self.curr_frontend = (
            "civetweb"
            if "civetweb" in self.rgw_section_options.get("rgw frontends")
            else "beast"
        )
        log.info("curr_frontend is set to: {}".format(self.curr_frontend))

        log.info("checking if ssl is configured in ceph.conf")
        self.curr_ssl = (
            True if "ssl" in self.rgw_section_options.get("rgw frontends") else False
        )
        log.info("curr_ssl_status from ceph conf is : {}".format(self.curr_ssl))

    @decorators.check_pem
    def set_frontend(self, frontend, **kwargs):
        """
        sets rgw_frontend in ceph conf and restart the services

        Parameters:
            frontend(char) : frontend port to be configured i.e beast or civetweb

        Returns:
            frontend: configured frontend
        """
        try:
            ssl = kwargs.get("ssl", False)
            if frontend not in SUPPORTED:
                raise RGWBaseException(
                    "got unsupported server config: {}\nsupported: {}".format(
                        frontend, SUPPORTED
                    )
                )
            log.info("setting rgw frontend")
            log.info("got frontend: {}".format(frontend))
            log.info("ssl: {}".format(ssl))

            if frontend == "civetweb":
                log.info("generating civetweb conf val")
                conf_val = (
                    "civetweb port={ip}:{ssl_port}s ssl_certificate=/etc/ceph/server.pem".format(
                        ip=self._ip, ssl_port=self._ssl_port
                    )
                    if ssl
                    else "civetweb port={ip}:{port}".format(
                        ip=self._ip, port=self._non_ssl_port
                    )
                )

            if frontend == "beast":
                log.info("generating beast conf val")
                conf_val = (
                    "beast ssl_endpoint={ip}:{ssl_port} ssl_certificate=/etc/ceph/server.pem".format(
                        ip=self._ip, ssl_port=self._ssl_port
                    )
                    if ssl
                    else "beast endpoint={ip}:{port}".format(
                        ip=self._ip, port=self._non_ssl_port
                    )
                )

            log.info("conf_val: {}".format(conf_val))
            self._ceph_conf.set_to_ceph_conf(self.section, "rgw frontends", conf_val)

            srv_restarted = self._rgw_service.restart()
            time.sleep(10)
            if srv_restarted is False:
                raise RGWBaseException("RGW service restart failed")
            else:
                log.info("RGW service restarted")
            self.curr_frontend = frontend
            self.curr_ssl = ssl
            log.info("frontend is set: {}".format(frontend))
            log.info("ssl status updated: {}".format(ssl))
            return frontend

        except RGWBaseException as e:
            log.error(e)
            log.error(traceback.format_exc())
            sys.exit(1)


class Frontend_CephAdm:
    """Frontend interface configured via cephadm."""

    def __init__(self):
        """Initialize the frontend values."""
        ceph_config = utils.exec_shell_cmd("sudo ceph config dump --format json")
        configs = loads(ceph_config)

        for config in configs:
            if config["name"] != "rgw_frontends":
                continue

            log.info(f"Configured RGW frontend is {config['value']}")
            self.curr_ssl = True if "ssl" in config["value"] else False
            self.curr_frontend = "beast"
            return

        raise RGWBaseException("No RGW frontend information found")

    def set_frontend(self, frontend, **kwargs):
        ssl = kwargs.get("ssl", False)
        frontend = "beast"
        self.curr_frontend = frontend
        self.curr_ssl = ssl
        log.info("frontend is set: {}".format(frontend))
        log.info("ssl status updated: {}".format(ssl))
        return frontend
