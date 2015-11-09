##dCheck : Domain check web app 

dCheck pulls information using commands *dig/whois/curl/nmap* to display domain related information on a webpage. It also has RESTful API to GET the information

###Features
1. The app is build with Python/Flask
2. Has an API system to pull information 
3. Gets and displays below information on webpage/API
  * DNS information
  * Header information
  * Whois information
  * IP information
  * Port information
4. Output from commands is filtered to give the desired results only
5. Javascript validation 

###API's
  * api/dig/<domain>
  * api/whois/<domain>
  * api/header/<domain>
  * api/ip/<domain>
  * api/nmap/<domain>
