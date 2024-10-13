using Cod.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cod.Platform.Identity.API
{
    public static class DependencyModule
    {
        private static volatile bool loaded;

        public static IServiceCollection AddIdentityAPI(this IServiceCollection services, IConfiguration configuration)
        {
            return services.AddIdentityAPI(configuration.Bind);
        }

        public static IServiceCollection AddIdentityAPI(this IServiceCollection services, Action<IdentityServiceOptions> identityOptions)
        {
            if (loaded)
            {
                return services;
            }

            loaded = true;

            services.AddIdentity(identityOptions);

            services.AddTransient<IAuthenticator, Authenticator>();
            services.AddTransient<ILoginRequestHandler, EmailLoginRequestHandler>();
            services.AddTransient<ILoginRequestHandler, PasswordLoginRequestHandler>();
            services.AddTransient<AuthenticationDomain>();
            services.AddTransient<Func<AuthenticationDomain>>(sp => () => sp.GetRequiredService<AuthenticationDomain>());
            services.AddTransient<IDomainRepository<AuthenticationDomain, User>, GenericDomainRepository<AuthenticationDomain, User>>();

            return services;
        }
    }
}
