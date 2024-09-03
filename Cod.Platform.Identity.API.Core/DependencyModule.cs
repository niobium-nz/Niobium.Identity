using Cod.Storage.Table;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cod.Platform.Identity.API
{
    public static class DependencyModule
    {
        public static IServiceCollection AddCodIdentityAPI(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddPlatformIdentity(configuration);
            services.AddTransient<IAuthenticator, Authenticator>();
            services.AddTransient<ILoginRequestHandler, EmailLoginRequestHandler>();
            services.AddTransient<ILoginRequestHandler, PasswordLoginRequestHandler>();
            services.AddTransient<IRepository<Login>, CloudTableRepository<Login>>();

            services.AddTransient<AuthenticationDomain>();
            services.AddTransient<Func<AuthenticationDomain>>(sp => () => sp.GetRequiredService<AuthenticationDomain>());
            services.AddTransient<IDomainRepository<AuthenticationDomain, User>, GenericDomainRepository<AuthenticationDomain, User>>();

            return services;
        }
    }
}
