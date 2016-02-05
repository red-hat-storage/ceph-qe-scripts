import test_backup_restore, test_bootable_vol, test_cinder_1, test_cinder_snapshot, test_glance, test_nova
import test_nova_snap, test_nova_with_vol
import lib.log as log


if __name__ == '__main__':


    log.info('running all the test cases')

    test_cinder_1.exec_test()           # test case 1

    test_cinder_snapshot.exec_test()    # test case 2

    test_bootable_vol.exec_test()       # test case 3

    test_backup_restore.exec_test_1()   # test case 4
    test_backup_restore.exec_test_2()   # test case 5

    test_glance.exec_test()             # test case 6

    test_nova.exec_test()               # test case 7

    test_nova_snap.exec_test()          # test case 8

    test_nova_with_vol.exec_test()      # test case 9


