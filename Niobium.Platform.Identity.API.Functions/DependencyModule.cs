using Niobium.Platform.StorageTable;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Niobium.Database.StorageTable;
using Niobium;
using Niobium.Platform;
using Niobium.Platform.Identity.API;

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

            builder.Services.AddTransient<CloudTableRepository<Dictionary<string, object>>>();
            builder.Services.AddTransient<IRepository<Dictionary<string, object>>>(sp =>
            {
                var repo = sp.GetRequiredService<CloudTableRepository<Dictionary<string, object>>>();
                repo.TableName = nameof(Profile);
                return repo;
            });

            builder.UsePlatform();
        }
    }
}
