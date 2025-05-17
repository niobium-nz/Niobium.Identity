using Cod;
using Cod.Database.StorageTable;
using Cod.Platform;
using Cod.Platform.Identity;
using Cod.Platform.Identity.API;
using Cod.Platform.StorageTable;
using Cod.Table.StorageAccount;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureFunctionsWebApplication(builder =>
    {
        builder.UsePlatform();
    })
    .ConfigureServices((context, services) =>
    {
        var isDevelopment = context.Configuration.IsDevelopmentEnvironment();
        services.AddApplicationInsightsTelemetryWorkerService()
                .ConfigureFunctionsApplicationInsights()
                .AddDatabase(context.Configuration.GetRequiredSection(nameof(StorageTableOptions)))
                    .PostConfigure<StorageTableOptions>(opt => opt.EnableInteractiveIdentity = isDevelopment)
                .AddIdentityAPI(context.Configuration.GetRequiredSection(nameof(IdentityServiceOptions)))
                .AddTransient<CloudTableRepository<Dictionary<string, object>>>()
                .AddTransient<IRepository<Dictionary<string, object>>>(sp =>
                {
                    var repo = sp.GetRequiredService<CloudTableRepository<Dictionary<string, object>>>();
                    repo.TableName = nameof(Profile);
                    return repo;
                });
    })
    .UseDefaultServiceProvider((_, options) =>
    {
        options.ValidateScopes = true;
        options.ValidateOnBuild = true;
    })
    .Build();

host.Run();
