#region

using System;
using System.Web;
using Sitecore;
using Sitecore.Data.Items;
using Sitecore.Diagnostics;
using Sitecore.SecurityModel;
using Sitecore.SecurityModel.Cryptography;
using Sitecore.Web;

#endregion

namespace ADFS.Authenticator.sitecore_modules.shell.FedAuthenticator
{
    public partial class Login : System.Web.UI.Page
    {
        #region Constants

        private const string StartUrl = "/sitecore/shell/default.aspx";

        #endregion

        #region Page Events

        protected void Page_Load(object sender, EventArgs e)
        {
            WriteCookie("sitecore_starturl", StartUrl);
            WriteCookie("sitecore_starttab", "advanced");
            Response.Redirect(StartUrl);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Determines whether this instance [can run application] the specified application name.
        /// </summary>
        /// <param name="applicationName">Name of the application.</param>
        /// <returns></returns>
        public static bool CanRunApplication(string applicationName)
        {
            Assert.IsNotNullOrEmpty(applicationName, "applicationName");
            if (!applicationName.StartsWith("/"))
                applicationName = "/sitecore/content/Applications/" + applicationName;
            Item item = null;
            using (new SecurityDisabler())
            {
                item = Client.CoreDatabase.GetItem(applicationName);
            }
            return item.Access.CanRead();
        }

        /// <summary>
        /// Writes the cookie.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="value">The value.</param>
        public static void WriteCookie(string name, string value)
        {
            Assert.ArgumentNotNull(name, "name");
            Assert.ArgumentNotNull(value, "value");

            if (name == WebUtil.GetLoginCookieName())
                value = MachineKeyEncryption.Encode(value);
            HttpContext.Current.Response.AppendCookie(new HttpCookie(name, value)
            {
                Expires = DateTime.Now.AddMonths(3),
                Path = "/sitecore/login"
            });
            var httpCookie = HttpContext.Current.Request.Cookies[name];

            if (httpCookie == null)
                return;

            httpCookie.Value = value;
        }

        #endregion
    }
}