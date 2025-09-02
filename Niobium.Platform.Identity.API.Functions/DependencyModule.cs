using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Niobium.Database.StorageTable;
using Niobium.Platform.StorageTable;

namespace Niobium.Platform.Identity.API.Functions
{
    public static class DependencyModule
    {
        private static volatile bool loaded;

        public static void AddIdentityAPI(this FunctionsApplicationBuilder builder)
        {
            if (loaded)
            {
                return;
            }

            loaded = true;

            builder.AddDatabase();
            builder.AddIdentity();
            builder.AddCore();

            builder.Services.Configure<IdentityAPIOptions>(o => builder.Configuration.GetSection(nameof(IdentityAPIOptions)).Bind(o));
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

            bool testMode = builder.Environment.IsDevelopment();
            if (!testMode)
            {
                httpClientBuilder.AddStandardResilienceHandler();
            }

            builder.UsePlatform();
        }
    }
}
