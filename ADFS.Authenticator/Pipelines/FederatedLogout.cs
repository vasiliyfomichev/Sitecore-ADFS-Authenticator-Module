using System;
using System.IdentityModel.Services;
using Sitecore.Diagnostics;
using Sitecore.Pipelines.Logout;

namespace Dustland.Sc.FedAuthenticator.Pipelines.Logout
{
    public class FederatedLogout
    {
        public void Process(LogoutArgs args)
        {
            Assert.ArgumentNotNull(args, "args");

            var authModule = FederatedAuthentication.WSFederationAuthenticationModule;
            WSFederationAuthenticationModule.FederatedSignOut(new Uri(authModule.Issuer), new Uri("https://uclasandbox.dustland.com"));
        }
    }
}