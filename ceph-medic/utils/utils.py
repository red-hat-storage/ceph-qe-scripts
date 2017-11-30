
class ERRORS(object):



    common_errs = {'ECOM1' : {'error_code': 'ECOM1:',
                       'desc': 'ceph configuration file can not be fo und at /etc/ceph/$cluster-name.conf',
                      },
              'ECOM2': {'error_code': 'ECOM2:',
                        'desc': 'ceph executable was not found',
                        },
              'ECOM3': {'error_code': 'ECOM3:',
                        'desc': 'The /var/lib/ceph directory does not exist or could not be collected',
                        },
              'ECOM4': {'error_code': 'ECOM4:',
                        'desc': 'The /var/lib/ceph directory was not owned by the ceph user.',
                        },
              'ECOM5' : {'error_code': 'ECOM5:',
                        'desc': 'The fsid defined in the configuration differs from other nodes in the cluster. The fsid must be the same for all nodes in the cluster.',
                        },



              }


    monitor_warnings = {
                'WMON1' : {
                    'warning_code' : 'WMON1:',
                    'desc' : 'Multiple monitor directories are found on the same host.'
                },
                'WMON2' : {

                    'warning_code': 'WMON2:',
                    'desc': 'Collocated OSDs in monitors nodes where found on the same host.'

                },

                'WOSD1': {

            'warning_code': 'WOSD1:',
            'desc': 'Multiple ceph_fsid values found in /var/lib/ceph/osd.'

        },

        'WOSD2': {

            'warning_code': 'WOSD2:',
            'desc': 'Setting osd pool default min size = 1 can lead to data loss because if minimum is not met, Ceph will not acknowledge the write to the client.'

        }

    }


    monitor_err= {

                'EMON1' : {

                    'error_code': 'EMON1:',
                    'desc': 'The secret key used in the keyring differs from other nodes in the cluster.'

                }



    }


invalid_inventory = '/invalid/invenotory/file'
invalid_ssh = '/invalid/ssh/file.conf'
invalid_cluster = 'invalid_name'
invalid_cmd='checkk'
get_os=['Ubuntu','Redhat']

invalid_cmd_err ={
    'Invalid Inventory' :{'Invalid inventory error': '--> the given inventory path does not exist: %s' %(invalid_inventory)},
    'Invalid SSH' : {'Invalid ssh error': '--> the given ssh config path does not exist: %s' %(invalid_ssh)},
    'Invalid Invenotory and SSH': {'Invalid invenotory and ssh error': '--> the given ssh config path does not exist: %s' % (invalid_ssh)},
    'Invalid Command' : {'Invalid command error':'Unknown command(s): %s' %(invalid_cmd)}
}
