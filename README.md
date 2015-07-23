What is Sitecore ADFS Authenticator?
==================================

The ADFS Authenticator is a rewritten version of the Fed Authenticator module in .NET 4.5, using the new System.IdentityModel namespaces, with specific configuration for the Active Directory Federated Services (ADFS).   

![Sitecore SignalR Tools](http://www.cmsbestpractices.com/wp-content/uploads/2015/07/sitecore-signalr-tools-logo.png)

The module implements the following additional features:  

- ADFS Logout  
- Authenticating users as Administrators

How to Install Sitecore ADFS Authenticator?
------------------------------------------------
> Publish the project directly into the \Website folder and copy the ADFS.Authenticator.config configuration file into \Website\App_Config\Include folder.

or 

> Install the precompiled [Sitecore ADFS Authenticator](https://marketplace.sitecore.net/en/modules/adfsauthenticator.aspx) module as a Sitecore package.


Contributing
----------------------
If you would like to contribute to this repository, please send a pull request.


License
------------
The project has been developed under the MIT license.


Related Sitecore Projects
--------------------------------
- [Solr for Sitecore](https://github.com/vasiliyfomichev/solr-for-sitecore) - pre-built Solr Docker images ready to be used with Sitecore out of the box.
- [Sitecore Lucene Term Highlighter](https://github.com/vasiliyfomichev/Sitecore-Solr-Search-Term-Highlight) - enables search term highlighting in Sitecore search results when used with Lucene.
- [Sitecore SignalR Tools](https://github.com/vasiliyfomichev/signalr-sitecore-tools) - commonly used Sitecore tools rebuilt using SignalR technology providing live updates and a modern interface.
 

Copyright 2015 Vasiliy Fomichev
