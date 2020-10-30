import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.utils.utils import FileOps
from v2.lib.exceptions import RGWBaseException, RGWIOGenException
import v2.utils.utils as utils
import logging

log = logging.getLogger()


def io_generator(fname, size, type='txt', op='create', **kwargs):
    """
        Function to generate IOs

        This function helps in creating file with random data

        Parameters:
            op(char): create or append.

        Returns:
            finfo : file information is returned.
    """
    finfo = {'name': fname,
             'size': None,
             'md5': None}

    # fname should include path, ex: /some/path/filename
    try:
        if op == 'create':
            log.info('in create')
            if type == 'txt':
                fcreate = 'base64 /dev/urandom | head -c %s > %s' % (size, fname)
                created = utils.exec_shell_cmd(fcreate)
                finfo['md5'] = utils.get_md5(fname)
                finfo['size'] = os.stat(fname).st_size
                if created is False:
                    raise RGWIOGenException("file %s creation error" % fname)
            return finfo
        if op == 'append':
            log.info('in modify or append')
            message = kwargs['message']
            log.info('message to append: %s' % message)
            fappend = open(fname, 'a+')
            fappend.write(message)
            fappend.close()
            finfo['md5'] = utils.get_md5(fname)
            finfo['size'] = os.stat(fname).st_size
            return finfo

    except RGWIOGenException as e:
        log.error(e)
        return False
