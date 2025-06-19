using Cod;
using Cod.Platform;
using Cod.Platform.Identity;
using Cod.Platform.Identity.API;
using Cod.Platform.StorageTable;
using Cod.Table.StorageAccount;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Niobium.Store.Functions
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

            builder.UsePlatform();
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
        }
    }
}
