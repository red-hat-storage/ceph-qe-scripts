import lib.log as log
import test_backup_restore
import test_bootable_vol
import test_cinder_1
import test_cinder_snapshot
import test_glance
import test_nova
import test_nova_snap
import test_nova_with_vol

if __name__ == "__main__":

    log.info("running all the test cases")

    test_cinder_1.exec_test()  # test case 1

    test_cinder_snapshot.exec_test()  # test case 2

    test_bootable_vol.exec_test()  # test case 3

    test_backup_restore.exec_test_1()  # test case 4
    test_backup_restore.exec_test_2()  # test case 5

    test_glance.exec_test()  # test case 6

    test_nova.exec_test()  # test case 7

    test_nova_snap.exec_test()  # test case 8

    test_nova_with_vol.exec_test()  # test case 9
