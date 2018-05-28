import log
import shlex
import random
import string
import subprocess


def exec_cmd(cmd):

    try:
        cmd = ' '.join(shlex.split(cmd))
        
        log.info('executing cmd: %s' % cmd)
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True)

        out, err = pr.communicate()

        if pr.returncode == 0:
            log.info('cmd executed')
            if out: 
                log.info('output:' + out)
            if err:    
                log.warning('warning:' + err)
            return out

        else:
            raise Exception("error: %s \nreturncode: %s" % (err, pr.returncode))

    except Exception, e :
        log.error('cmd execution failed')
        log.error(e)
        return False


def random_string():
    temp_str = ''.join(
        [random.choice(string.ascii_letters) for _ in xrange(10)])
    return temp_str