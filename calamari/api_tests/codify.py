import config as config
import utils.log as log

# import tests cases
import test_api_config
import test_api_crush_map
import test_api_crush_node
import test_api_crush_rule_set
import test_api_crush_rule
import test_api_crush_type
import test_api_logs
import test_api_mon
import test_api_pool
import test_api_request
import test_api_saltkey
import test_api_server_withinCluster
import test_api_sync
import test_api_event
import test_api_osd
import test_api_cli
import logout

if __name__ == '__main__':

    config_data = config.get_config()

    if not config_data['auth']:
        log.error('auth failed')

    else:
        # call test_cases

        test_api_cli.exec_test(config_data)                     # test_id:0
        test_api_config.exec_test(config_data)                  # test_id:1
        test_api_crush_map.exec_test(config_data)               # test_id:2
        test_api_crush_node.exec_test(config_data)              # test_id:3
        test_api_crush_rule_set.exec_test(config_data)          # test_id:4
        test_api_crush_rule.exec_test(config_data)              # test_id:5
        test_api_crush_type.exec_test(config_data)              # test_id:6
        test_api_logs.exec_test(config_data)                    # test_id:7
        test_api_mon.exec_test(config_data)                     # test_id:8
        test_api_pool.exec_test(config_data)                    # test_id:9
        test_api_request.exec_test(config_data)                 # test_id:10
        test_api_saltkey.exec_test(config_data)                 # test_id:11
        test_api_server_withinCluster.exec_test(config_data)    # test_id:12
        test_api_sync.exec_test(config_data)                    # test_id:13
        test_api_event.exec_test(config_data)                   # test_id:14
        test_api_osd.exec_test(config_data)                     # test_id:15

        logout.exec_test(config_data)


