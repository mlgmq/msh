import sys
import multiprocessing
import paramiko
import getopt
import os.path
from datetime import datetime
import socket


def print_output(host_info):
    if not host_info:
        return None
    print('user:[{}] run cmd on host:[{}] status:[{}]'.format(host_info['user'], host_info['host'], host_info['status']))
    output_file_path = host_info['output_file_path']
    if not os.path.exists(output_file_path):
        os.makedirs(output_file_path)
    filename = '{}{}{}_{}.log'.format(output_file_path, os.path.sep, host_info['host'], host_info['user'])
#    print('output filename:'+filename)
    fileHandler = open(filename, "a+")
    header = 'host info===================================\n'
    header = header + 'host:[{}]\nuser:[{}]\nkey_filename:[{}]\nresult status:[{}]\n'.format(host_info['host'], host_info['user'], host_info['key_filename'], host_info['status'])
    header = header + 'command output------------------------------\n'
    fileHandler.write(header)
    output = host_info['output']
    if output :
        for line in output:
            fileHandler.write(line)
    fileHandler.close()

  
class SSHConnect():

    def __init__(self, hostname, username, password, key_filename, connect_timeout):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.connect_timeout = connect_timeout
        self.status = 'succeed'

    def connect(self):
        try:
            self.__sshclient = None
            self.__sshclient = paramiko.SSHClient()
            self.__sshclient.load_system_host_keys()
            self.__sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.key_filename == '' :
                self.__sshclient.connect(
                    hostname=self.hostname,
                    username=self.username,
                    password=self.password,
                    timeout=self.connect_timeout
                )
            else:
                self.__sshclient.connect(
                    hostname=self.hostname,
                    username=self.username,
                    key_filename=self.key_filename,
                    timeout=self.connect_timeout
                )
        except paramiko.BadHostKeyException:
            self.status = 'BadHostKeyException'
        except paramiko.AuthenticationException:
            self.status = 'AuthenticationException'
        except paramiko.SSHException:
            self.status = 'SSHException'
        except socket.error:
            self.status = 'socket.error'
        except :
            self.status = 'connect error'
        
        return self.connected()

    def close(self):
        try:
            self.__sshclient.close()
        except:
            pass

    def connected(self):
        try:
            active = self.__sshclient.get_transport().is_authenticated()
        except:
            active = False
        return active

    def cmd(self, cmd):
        try:
            if self.connected() and cmd:
                # print('running command:::' + cmd)
                stdin, stdout, stderr = self.__sshclient.exec_command(cmd)
                output = stdout.readlines()
                return output
        except:
            try:
                self.__sshclient.close()
            except:
                self.status = 'exec command error'
            return None

           
class mshRun(object):

    def __init__(self, processes=2):
        self.version = '0.1'
        self.processes = processes
        self.connect_timeout = 40
        self.host_details = []
        self.workdir = os.path.abspath(os.curdir)
        self.default_hostfile = self.__trailing('host_list', 'hosts')  
        self.default_cmd_file = self.__trailing('run_cmds', '')        
        self.output_file_path = self.__trailing(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"), 'output')
        self.deps_files = []
        self.__cmd = "true"

    def add_ssh_host(self, host, user=None, password=None, key_filename=None):
#        print('host:' + host + ' user:' + user + ' password:' + password + ' key_filename:' + key_filename)
        if host and user:
            host_info = {'host': host, 'user': user,
                 'password': password, 'key_filename': key_filename,
                 'connect_timeout': self.connect_timeout,
                 'output_file_path':self.output_file_path,
                 'cmd': self.__cmd, 'output':None, 'status':'unknown', 'deps_files':self.deps_files}
            self.host_details.append(host_info)
        else:
            print('host:{} could not be added\'.format(host)')

    def __trailing(self, path, prepix=''):
        if path.find(os.path.sep) != -1 :
            fpath = path
        else:
            fpath = os.path.join(self.workdir, prepix, path)
        return fpath
        
    def __load_hosts(self, host_filename):
        filename = self.__trailing(host_filename, 'hosts')
        print("load_hosts:", filename)
        try:
            fileParser = open(filename, 'r')
        except IOError:
            print("[!] Could not open file " + filename)
            return None 
        except:
            print("[!] Could not access file " + filename)
            return None
        for line in fileParser.readlines():
            newLine = line.replace('\n', '')
            if (newLine[0:1] != '#') :
                host = list(newLine.split())
                if len(host) == 4 :
                    keyfile = host[3] 
                else:
                    keyfile = ''
                if len(host) >= 3 :
                    self.add_ssh_host(host[0], host[1] , host[2], keyfile)

    def __load_cmd_files(self, cmd_filename):
        filename = self.__trailing(cmd_filename)
        print("load_cmd_files:", filename)
        try:
            fileParser = open(filename, 'r')
        except IOError:
            print("[!] Could not open file " + filename)
            return None 
        except:
            print("[!] Could not access file " + filename)
            return None
        try:
            while True:
                line = fileParser.readline()
                line = line.replace('\n', '')
                if line and (line[0:1] != '#'):
                    self.__cmd = self.__cmd + ";" + line
                else:
                    break
        finally:
            fileParser.close()

        print("cmd::::" + self.__cmd)        

    def __load_deps_files(self, deps_filename):
        filename = self.__trailing(deps_filename)
        print("load_deps_files_form_file:", filename)
        try:
            fileParser = open(filename, 'r')
        except IOError:
            print("[!] Could not open file " + filename)
            return None 
        except:
            print("[!] Could not access file " + filename)
            return None
        for line in fileParser.readlines():
            newLine = line.replace('\n', '')
            if (newLine[0:1] != '#') :
                r = list(newLine.split())
                if len(r) == 3 :
                    self.deps_files.append({'ops':r[0], 'localpath': r[1], 'remotepath': r[2]})

    def __start(self):
        opts, args = getopt.getopt(sys.argv[1:], '-h-f:-v-p:-t:-o:-d:-c:', ['help', 'filename=', 'version', 'process=', 'connect_timeout=', 'output=', 'deps_files=', 'cmd_file='])
        for opt_name, opt_value in opts:
            if opt_name in ('-h', '--help'):
                print(sys.argv[0] + ' [-h] [-v]  [-p process] [-t connect_timeout]')
                print('    [-f host_filename] [-o output_file_path] [-d deps_files] [-c cmd_file]')
                print(sys.argv[0] + '[--help] [--version] [--process process] [--connect_timeout connect_timeout]')
                print('    [--filename host_filename] [--output output_file_path]  [--deps_files deps_files] [--cmd_file cmd_file]')
                sys.exit()
            if opt_name in ('-v', '--version'):
                print("[*] Version is {} ".format(self.version))
                sys.exit()
            if opt_name in ('-f', '--filename'):
                self.default_hostfile = ''
                self.__load_hosts(opt_value)
            if opt_name in ('-p', '--process'):
                self.processes = opt_value
            if opt_name in ('-t', '--connect_timeout'):
                self.connect_timeout = opt_value
            if opt_name in ('-o', '--output'):
                self.output_file_path = self.__trailing(opt_value, 'output')
            if opt_name in ('-d', '--deps_files'):
                self.__load_deps_files(opt_value)
            if opt_name in ('-c', '--cmd_file'):
                self.default_cmd_file = ''
                self.__load_cmd_files(opt_value)

    def run(self):
        self.__start()
        if self.default_cmd_file != '' :
            self.__load_cmd_files(self.default_cmd_file)
        self.__load_deps_files('deps_files')
        if self.default_hostfile != '' :
            self.__load_hosts(self.default_hostfile)
                    
        pool = multiprocessing.Pool(processes=self.processes)
        try:
            for host_info in self.host_details:
                pool.apply_async(_run_ssh_cmd, [host_info], callback=print_output)
            pool.close()
            pool.join()
            return None
        except:
            pool.terminate()
            raise 'run error!'


def Parsing_Path(host, p_path):
    path = p_path
    path = path.replace('$CURRDIR', os.path.abspath(os.curdir))
    path = path.replace('$HOST', host['host'])
    path = path.replace('$OUTPUT_PATH', host['output_file_path'])
    return path


def transfer_file(host_info, to_srv='up'):
    try:
        try:
            t = paramiko.Transport((host_info['host'], 22))
            if host_info['key_filename'] == '' :
                t.connect(username=host_info['user'], password=host_info['password'])
            else:
                private_key = paramiko.RSAKey.from_private_key_file(host_info['key_filename'])
                t.connect(username=host_info['user'], pkey=private_key)
            sftp = paramiko.SFTPClient.from_transport(t)
            for script in host_info['deps_files']:
                if to_srv == 'up' and script['ops'] == 'up':
                    sftp.put(Parsing_Path(host_info, script['localpath']), Parsing_Path(host_info, script['remotepath']))
                if to_srv == 'down' and script['ops'] == 'down':
                    sftp.get(Parsing_Path(host_info, script['remotepath']), Parsing_Path(host_info, script['localpath']))
            t.close()
        except Exception as e:
            print(e.message)
    except:
        pass


def _run_ssh_cmd(host_info):
    try:
        sshcon = SSHConnect(
                  host_info['host'],
                  host_info['user'],
                  host_info['password'],
                  host_info['key_filename'],
                  host_info['connect_timeout']
                  )
        sshcon.connect()
        if sshcon.connected():
            transfer_file(host_info, 'up')
        output = sshcon.cmd(host_info['cmd'])
        if sshcon.connected():
            transfer_file(host_info, 'down')
        # host_info['status'] = sshcon.status
        # host_info['output'] = output
        host_info.update({ 'status': sshcon.status  })
        host_info.update({ 'output': output  })
        sshcon.close()
    finally:
        return host_info


if __name__ == '__main__':
    mshRun = mshRun()
    mshRun.run()
    print("Completed!")
