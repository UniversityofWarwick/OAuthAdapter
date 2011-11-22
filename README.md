OAuth adapter
=============

Adds support for OAuth requests to Titanium Mobile.

Example Usage
=============

  var warwickAuthAdapter = new OAuthAdapter({
    signatureMethod: 'HMAC-SHA1',
    consumerSecret: 'your-consumer-secret',
    consumerKey: 'your-consumer-key',
    requestTokenURL: 'https://websignon.warwick.ac.uk/oauth/requestToken?scope=urn%3Astart.warwick.ac.uk%3Aportal%3Aservice%2Burn%3Asearch.warwick.ac.uk%3Asearch%3Aservice',
    authorizeTokenURL: 'https://websignon.warwick.ac.uk/oauth/authorise',
    accessTokenURL: 'https://websignon.warwick.ac.uk/oauth/accessToken',
    serviceName: 'warwick',
    callbackURL: 'local://callback'
  });
  
  if(!warwickAuthAdapter.authorized()) {
    warwickAuthAdapter.send({
      url: 'https://start.warwick.ac.uk/portal/api/user',
      successCallback: function(){
        // We've successfully accessed a private URL
      },
      failureCallback: function(){
        // Failure message in this.responseText;
      }
    });
  }

Released under the Apache License, Version 2.0
==============================================

Copyright 2011 University of Warwick

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

