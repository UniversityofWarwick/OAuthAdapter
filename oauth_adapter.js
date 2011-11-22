/*
 * Copyright 2011 University of Warwick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var OAuthAdapter = function(options){
	// Optional parameters
	
	var signatureMethod = options.signatureMethod || 'HMAC-SHA1';
	
	// Mandatory parameters
	
	var consumerSecret = options.consumerSecret;
    var consumerKey = options.consumerKey;
    
    var requestTokenURL = options.requestTokenURL;
    var authorizeTokenURL = options.authorizeTokenURL;
    var accessTokenURL = options.accessTokenURL;
    
    var serviceName = options.serviceName;
    
    var callbackURL = options.callbackURL;
    
    var now = new Date();
    var tokenExpiry = options.tokenExpiry || new Date((now.setFullYear(now.getFullYear() + 1))); // Default 1 year for new tokens
    
    var libDirectory = options.libDirectory || Ti.Filesystem.resourcesDirectory + 'lib/oauth/'; // Locations of oauth.js and sha1.js
    
    // Private variables   
     
    var successCallback;
    var authRequiredCallback;
    var failureCallback;

    var requestToken;
    var requestTokenSecret;    
    var accessToken;
    var accessTokenSecret;
    
    var authWindow;
    var authWindowWebView;
    
    var actionsQueue = [];
    
    
    // Setup
    
    Ti.include(libDirectory + 'oauth.js');
    Ti.include(libDirectory + 'sha1.js');
    
    // Check for and load an existing access token
    loadAccessToken();
    
    // Public methods
    this.authorized = function(){
    	return accessToken != null && accessTokenSecret != null;
    };
    
    this.send = send;
    
    // Private methods
    
    function send(options){
    	var url = options.url;
    	var method = options.method || 'GET';
    	var postBody = options.postBody;
    	
    	successCallback = options.successCallback;
    	authRequiredCallback = options.authRequiredCallback || doAuth; // Handle token request if different from the default
    	failureCallback = options.failureCallback;
    	
    	if (accessToken == null || accessTokenSecret == null) {
    		// store this request for when the auth is complete
    		actionsQueue.push(options);
    		authRequiredCallback();
    	} else {
    		
    		var message = createMessage(url);
    		message.method = method;
        	message.parameters.push(['oauth_token', accessToken]);
        	OAuth.setTimestampAndNonce(message);
        	OAuth.SignatureMethod.sign(message, {
        		consumerSecret: consumerSecret,
        		tokenSecret: accessTokenSecret
    		});
    		
    		var client = Ti.Network.createHTTPClient();
    		client.open(method, url);
    		client.setRequestHeader("Authorization", "OAuth " + kvArrayToAuthString(message.parameters));
    		client.onload = successCallback;
    		client.onerror = failureCallback;
    		
    		if(method == "GET"){
				client.send();
    		} else {
    			client.send(postBody);
    		}
    		
    	}
    };
    
    var kvArrayToAuthString = function(array){
    	var result = [];
    	for (var i=0, length = array.length; i<length; i++) {
    		result.push(OAuth.percentEncode(array[i][0]) + '="' + OAuth.percentEncode(array[i][1]) + '"');
    	}
    	return result.join(', ');
    };
    
    function loadAccessToken(){
    	var file = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory, serviceName + '.oauth.config');
        if (file.exists == false) 
        	return;

        var contents = file.read();
        if (contents == null) 
        	return;

        try {
            var config = JSON.parse(contents.text);
        } catch(ex) {
            return;
        }
        
        if(!config)
        	config = {};
        
        if (!config.expiry || new Date(config.expiry) > new Date()) {
        	tokenExpiry = new Date(config.expiry);
        	if (config.accessToken) 
        		accessToken = config.accessToken;
        	if (config.accessTokenSecret) 
        		accessTokenSecret = config.accessTokenSecret;
        }
    };
    
    var saveAccessToken = function(){
        var file = Ti.Filesystem.getFile(Ti.Filesystem.applicationDataDirectory, serviceName + '.oauth.config');
        if (file == null) 
        	file = Ti.Filesystem.createFile(Ti.Filesystem.applicationDataDirectory, serviceName + '.oauth.config');
        	
        file.write(JSON.stringify({
            accessToken: accessToken,
            accessTokenSecret: accessTokenSecret,
            expiry: tokenExpiry.valueOf()
        }));
    };
    
    var createMessage = function(url) {
        var message = {
            action: url,
            method: 'GET',
            parameters: []
        };
        message.parameters.push(['oauth_consumer_key', consumerKey]);
        message.parameters.push(['oauth_signature_method', signatureMethod]);
        return message;
    };
    
    var doAuth = function(){
    	
    	// First get the request token
    	

    	var message = createMessage(requestTokenURL);
        OAuth.setTimestampAndNonce(message);
        OAuth.SignatureMethod.sign(message, {
        	consumerSecret: consumerSecret,
        	tokenSecret: ''
    	});
        

        var client = Ti.Network.createHTTPClient();
    	client.open('GET', requestTokenURL);
    	client.setRequestHeader("Authorization", "OAuth " + kvArrayToAuthString(message.parameters));
    	client.onload = processRequestToken;
    	client.onerror = failureCallback;
    		
		client.send();
    	
    };
    
    var processRequestToken = function(){
    	var responseParams = OAuth.getParameterMap(this.responseText);
        requestToken = responseParams['oauth_token'];
        requestTokenSecret = responseParams['oauth_token_secret'];
        
        
        // Then authorize the request token
        
        authWindow = Ti.UI.createWindow({
            modal: true,
            navBarHidden: true
        });
        
		var view = Ti.UI.createView({

        });
        
        authWindowWebView = Ti.UI.createWebView({
    		url: authorizeTokenURL + '?oauth_token=' + requestToken + '&oauth_callback=' + encodeURIComponent(callbackURL),
			autoDetect:[Ti.UI.AUTODETECT_NONE]
    	});
    	authWindowWebView.addEventListener('beforeload', detectCallbackURLTrue)
    	authWindowWebView.addEventListener('error', detectCallbackURLFalse);
    	view.add(authWindowWebView);
    	
    	var label = Ti.UI.createLabel({
            top:0,
            right:0,
            width:30,
            height:30,
            backgroundImage: libDirectory + 'closebox.png'
            
		});
		label.addEventListener('click', function(){
			authWindow.close();
		});
		view.add(label);
    	
    	authWindow.add(view);
    	authWindow.open();
    };
    
    var detectCallbackURLTrue = function(e){
    	if (e.source.url.indexOf(callbackURL) >= 0)
    		completeCallback();
    };
    
    var detectCallbackURLFalse = function(e){
		if (e.source.url.indexOf(encodeURIComponent(callbackURL)) >= 0)
    		completeCallback();
    };
    
    var completeCallback = function(){
    	authWindowWebView.removeEventListener('beforeload', detectCallbackURLTrue)
    	authWindowWebView.removeEventListener('error', detectCallbackURLFalse);
    	authWindow.close();
    	getAccessToken();
    };
    
    var getAccessToken = function(){    
        var message = createMessage(accessTokenURL);
        message.parameters.push(['oauth_token', requestToken]);
        OAuth.setTimestampAndNonce(message);
        OAuth.SignatureMethod.sign(message, {
        	consumerSecret: consumerSecret,
        	tokenSecret: requestTokenSecret
    	});
        
        var client = Ti.Network.createHTTPClient();
    	client.open('GET', accessTokenURL);
    	client.setRequestHeader("Authorization", "OAuth " + kvArrayToAuthString(message.parameters));
    	client.onload = processAccessToken;
    	client.onerror = failureCallback;
    		
		client.send();
    };
	
	var processAccessToken = function(){
		var responseParams = OAuth.getParameterMap(this.responseText);
        accessToken = responseParams['oauth_token'];
        accessTokenSecret = responseParams['oauth_token_secret'];
        saveAccessToken();
        processQueue();
	};
	
	var processQueue = function() {
    while ((q = actionsQueue.shift()) != null)
      send(q);
  };
}
