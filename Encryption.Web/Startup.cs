using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Encryption.Web.Startup))]
namespace Encryption.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
