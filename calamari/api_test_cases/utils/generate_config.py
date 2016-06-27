import yaml
import argparse

"""
Example arguments :
python generate_config.py -http https -ip 10.8.128.63 -port 8002 -u admin -p admin123 -log /tmp/logs
"""

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation configuration')

    parser.add_argument('-http', dest="http", default="https",
                        help='Input type of the protocol: http or https')

    parser.add_argument('-ip', dest='ip', help='Enter IP address')

    parser.add_argument('-port', dest='port', help='Enter port number')

    parser.add_argument('-u',  dest='uname', help='Enter calamari username')

    parser.add_argument('-p',  dest='pwd', default='8002', help='Enter calamari password')

    parser.add_argument('-log', dest='log', default='/tmp/log',
                        help='Enter log copy location')

    args = parser.parse_args()

    data = dict(
        calamari=dict(
            http=args.http,
            ip=args.ip,
            port=args.port,
            username=args.uname,
            password=args.pwd,
            log_copy_location=args.log
        )
    )

    with open('../config.yaml', 'w') as outfile:
        outfile.write(yaml.dump(data, default_flow_style=False))

