#region

using System;
using System.IdentityModel.Services;
using Sitecore.Diagnostics;

#endregion

namespace ADFS.Authenticator.sitecore_modules.Shell.FedAuthenticator
{
    public partial class Logout : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (IsPostBack) return;

            Log.Info(Sitecore.Context.User.Name + " logged out from federated SSO.", this);
            var authModule = FederatedAuthentication.WSFederationAuthenticationModule;

            WSFederationAuthenticationModule.FederatedSignOut(new Uri(authModule.Issuer), new Uri(Request.Url.Scheme + "://" + Request.Url.Host));
        }
    }
}