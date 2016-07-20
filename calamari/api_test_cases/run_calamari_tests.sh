#!/usr/bin/env bash
# example :
# sh run_calamari_tests.sh -http=https -ip=10.8.128.63 -port=8002 -u=admin -p=admin123 -l=/tmp/log
set -x

for i in "$@"
do
case $i in
    -http=*|--http_protocol=*)
    HTTP="${i#*=}"
    ;;
    -ip=*|--ip_addr=*)
    IP="${i#*=}"
    ;;
    -port=*|--port_no=*)
    PORT="${i#*=}"
    ;;
    -u=*|--username=*)
    UNAME="${i#*=}"
    ;;
    -p=*|--passwd=*)
    PASSWD="${i#*=}"
    ;;
    -l=*|--log_path=*)
    LOG="${i#*=}"
    ;;
esac
done
echo protocol = ${HTTP}
echo IP = ${IP}
echo PORT = ${PORT}
echo USERNAME = ${UNAME}
echo PASSWORD = ${PASSWD}
echo LOG_PATH = ${LOG}

[ -z $HTTP ] && HTTP=https
[ -z $IP ] && IP=localhost
[ -z $PORT ] && PORT=8002
[ -z $UNAME ] && UNAME=admin
[ -z $PASSWD ] && PASSWD=admin
[ -z $LOG ] && LOG="/tmp/apilog"

echo protocol = ${HTTP}
echo IP = ${IP}
echo PORT = ${PORT}
echo USERNAME = ${UNAME}
echo PASSWORD = ${PASSWD}
echo LOG_PATH = ${LOG}

virtualenv venv
source venv/bin/activate
pip install pyyaml
pip install requests
pip install names

python generate_config.py -http ${HTTP} -ip ${IP} -port ${PORT} -u ${UNAME} -p ${PASSWD} -log ${LOG}
python codify.py
