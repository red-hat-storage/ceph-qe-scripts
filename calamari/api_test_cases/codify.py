from utils.utils import get_calamari_config
import argparse
import libs.log as log
import test_cli, test_config, test_crush_map, test_crush_rule, test_crush_rule_set, test_crush_type, test_event, \
    test_log, test_mon, test_osd, test_osd_config, test_pool, test_salt_key, test_server, test_sync, test_user


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    tests = [
        test_cli.exec_test(calamari_config),
        test_config.exec_test(calamari_config),
        test_crush_map.exec_test(calamari_config),
        test_crush_rule.exec_test(calamari_config),
        test_crush_rule_set.exec_test(calamari_config),
        test_crush_type.exec_test(calamari_config),
        test_event.exec_test(calamari_config),
        test_log.exec_test(calamari_config),
        test_mon.exec_test(calamari_config),
        test_osd.exec_test(calamari_config),
        test_osd.exec_test2(calamari_config),
        test_osd_config.exec_test(calamari_config),
        test_pool.exec_test(calamari_config),
        test_salt_key.exec_test(calamari_config),
        test_server.exec_test1(calamari_config),
        test_server.exec_test2(calamari_config),
        test_sync.exec_test(calamari_config),
        test_user.exec_test(calamari_config)
    ]

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
