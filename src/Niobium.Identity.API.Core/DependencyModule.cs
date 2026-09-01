using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Niobium.Database.StorageTable;
using Niobium.Platform.Identity;

namespace Niobium.Identity.API
{
    public static class DependencyModule
    {
        private static volatile bool loaded;

        public static TBuilder AddCore<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
            => builder.AddCore(builder.Configuration.GetSection(nameof(IdentityAPIOptions)).Bind);

        public static TBuilder AddCore<TBuilder>(this TBuilder builder, Action<IdentityAPIOptions>? options) where TBuilder : IHostApplicationBuilder
        {
            if (loaded)
            {
                return builder;
            }

            loaded = true;

            Platform.StorageTable.DependencyModule.AddDatabase(builder);
            Platform.Identity.DependencyModule.AddIdentity(builder);

            builder.Services.Configure<IdentityAPIOptions>(o => options?.Invoke(o));

            builder.Services.AddTransient<ProfileServiceAuthorizor>();
            builder.Services.AddTransient<IAuthenticator, Authenticator>();
            builder.Services.AddTransient<ILoginRequestHandler, EmailLoginRequestHandler>();
            builder.Services.AddTransient<ILoginRequestHandler, PasswordLoginRequestHandler>();
            builder.Services.AddDomain<AuthenticationDomain, User>();

            builder.Services.AddTransient<CloudTableRepository<Dictionary<string, object>>>();
            builder.Services.AddTransient<IRepository<Dictionary<string, object>>>(sp =>
            {
                CloudTableRepository<Dictionary<string, object>> repo = sp.GetRequiredService<CloudTableRepository<Dictionary<string, object>>>();
                repo.TableName = nameof(Profile);
                return repo;
            });

            IHttpClientBuilder httpClientBuilder = builder.Services.AddHttpClient(Constants.DefaultHttpClientName, httpClient =>
            {
                httpClient.BaseAddress = new Uri("https://login.microsoftonline.com/");
            });

            bool devMode = builder.Configuration.IsDevelopmentEnvironment();
            if (!devMode)
            {
                httpClientBuilder.AddStandardResilienceHandler();
            }

            return builder;
        }
    }
}
