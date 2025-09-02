using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;

namespace Niobium.Platform.Identity.API
{
    public static class DependencyModule
    {
        private static volatile bool loaded;

        public static void AddCore(this IFunctionsWorkerApplicationBuilder builder)
        {
            if (loaded)
            {
                return;
            }

            loaded = true;

            builder.Services.AddTransient<ProfileServiceAuthorizor>();
            builder.Services.AddTransient<IAuthenticator, Authenticator>();
            builder.Services.AddTransient<ILoginRequestHandler, EmailLoginRequestHandler>();
            builder.Services.AddTransient<ILoginRequestHandler, PasswordLoginRequestHandler>();
            builder.Services.AddDomain<AuthenticationDomain, User>();
        }
    }
}
