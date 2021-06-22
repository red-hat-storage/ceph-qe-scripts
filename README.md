This repository contains scripts for testing Ceph. We recommend porting the scripts to `ceph-qe-scripts` once it has been found to be reliable and passes the established criteria

Scripts here can be in any language (Python/Perl/PHP/Shell etc)

#### Assumptions:
Script can assume the Ceph Cluster is formed and has to mention
the requirement of OSD/Mon/RGW nodes in its header comment

#### Example: 
     # Owner: Name 
     # Email: EmailId
     # Script to test the RBD Negative CLI's
     # This script requires 3 nodes with 2 mons and 2 osd's on each node
     # This script also needs a client and should be run on client
     #  Test Description:
     #   a) Invoke various rbd cli commands with negative options
     #   b) Verify the cli throws appropriate error message
     #   c)
     #  Success: exit code: 0
     #  Failure: Non Zero Exit or ERROR message in output

#### Development Guidelines
An attempt is made to follow a set of style guidelines for clarity. As we grow and have more contributors, it becomes essential for us to follow some standard practices. We use: 
- black 
- isort    
   
##### black
```
Install in your environment using
$ pip3 install black

# format file
$ black <filename>

where `filename` is
    - a relative or absolute path of the file
    - a relative or absolute path of a directory # for running for set of files

# format full project
$ black .
```

##### isort
```
Install in your enviornemnt using
$ pip3 install isort

# formatting code with isort
$ isort <filename>

where `filename`
- a relative or absolute path of the file
- a relative or absolute path of a directory
```
