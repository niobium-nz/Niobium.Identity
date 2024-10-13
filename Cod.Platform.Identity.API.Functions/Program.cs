using Cod.Platform.Identity;
using Cod.Platform.Identity.API;
using Cod.Table.StorageAccount;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureFunctionsWebApplication()
    .ConfigureServices((context, services) =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        var isDevelopment = context.Configuration.GetValue<string>(Cod.Platform.Constants.ServiceEnvironment) == Cod.Platform.Constants.DevelopmentEnvironment;
        services.AddTable(new StorageTableOptions
        {
            EnableInteractiveIdentity = isDevelopment,
            ConnectionString = context.Configuration.GetValue<string>($"{nameof(StorageTableOptions)}:{nameof(StorageTableOptions.ConnectionString)}"),
        }, azureClientDefaults: context.Configuration.GetSection("AzureDefaults"))
        .AddIdentityAPI(context.Configuration.GetRequiredSection(nameof(IdentityServiceOptions)));
    })
    .UseDefaultServiceProvider((_, options) =>
    {
        options.ValidateScopes = true;
        options.ValidateOnBuild = true;
    })
    .Build();

host.Run();
