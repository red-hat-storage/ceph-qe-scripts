from utils.utils import get_calamari_config
import argparse, os
import libs.log as log
import test_cli, test_config, test_crush_map, test_crush_rule, test_crush_rule_set, test_crush_type, test_event, \
    test_log, test_info, test_mon, test_osd, test_osd_config, test_pool, test_salt_key, test_server, test_sync, \
    test_user
from shutil import copyfile
import sys
import time

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    # sleep for few seconds in case calamri and supervisor services are restarted

    time.sleep(15)

    tests = [
        test_cli.exec_test(calamari_config),  # test id  1
        test_config.exec_test(calamari_config),  # test id  2
        test_crush_map.exec_test(calamari_config),  # test id  3
        # test_crush_rule.exec_test(calamari_config),  # test id  4
        test_crush_rule_set.exec_test(calamari_config),  # test id  5
        test_crush_type.exec_test(calamari_config),  # test id  6
        test_event.exec_test(calamari_config),  # test id  7
        test_mon.exec_test(calamari_config),  # test id  8
        # test_log.exec_test(calamari_config),  # test id  9
        test_info.exec_test(calamari_config),  # test id  10
        # test_osd.exec_test(calamari_config),  # test id  11.1
        test_osd.exec_test2(calamari_config),  # test id  11.2
        test_osd_config.exec_test(calamari_config),  # test id  12
        test_pool.exec_test(calamari_config),  # test id  13
        # test_salt_key.exec_test(calamari_config),  # test id  14
        test_server.exec_test1(calamari_config),  # test id  15.1
        # test_server.exec_test2(calamari_config),  # test id  15.2
        test_sync.exec_test(calamari_config),  # test id  16
        # test_user.exec_test(calamari_config)  # test id  17
    ]

    # the commented test cases are fialing and bugs for them are filed
    # need to add BZ numbers.

    all_tests_exec = [test for test in tests]

    log.info('-------------------- Summary -------------------------')

    log.info('--------- Passed ----------')

    passed = [log.info('\nTest id: %s\nAPI: %s\n---------' % (passed['id'], passed['name']))
              for passed in all_tests_exec if passed['status']]

    log.info('--------- Failed ----------')

    failed = [log.info('\nTest id: %s\nAPI: %s\n---------' % (failed['id'], failed['name']))
              for failed in all_tests_exec if not failed['status']]

    log.info('--------------->Total Tests Passed: %s' % len(passed))
    log.info('--------------->Total Tests Failed: %s' % len(failed))

    print 'copying the log file to the log location defined'

    copyfile(log.LOG_NAME,
             os.path.join(calamari_config['log_copy_location'], log.LOG_NAME))

    if len(failed) > 0:
        sys.exit(1)

    else:
        sys.exit(0)
