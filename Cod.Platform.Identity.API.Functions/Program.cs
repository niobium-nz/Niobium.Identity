using Cod.Platform.Identity;
using Cod.Platform.Identity.API;
using Cod.Storage.Table;
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

        services.AddPlatformIdentity(
            new IdentityServiceOptions
            {
                IDTokenPrivateKey = context.Configuration.GetValue<string>("ID_TOKEN_PRIVATE_KEY"),
                IDTokenPrivateKeyPasscode = context.Configuration.GetValue<string>("ID_TOKEN_PRIVATE_KEY_PASSCODE"),
                TokenValidity = TimeSpan.FromHours(context.Configuration.GetValue<int>("TOKEN_VALIDITY_HOURS")),
                EnableIdentityEndpoints = false,
            },
            new StorageTableOptions
            {
                ServiceEndpoint = context.Configuration.GetSection(Cod.Storage.Table.Constants.AppSettingStorageTable).GetValue<string>(Cod.Storage.Table.Constants.AppSettingStorageTableServiceUri),
                EnableInteractiveIdentity = context.Configuration.GetValue<string>(Cod.Platform.Constants.ServiceEnvironment) == Cod.Platform.Constants.DevelopmentEnvironment,
                AzureStorageTableDefaults = context.Configuration.GetSection("AzureDefaults"),
            });

        services.AddCodIdentityAPI();
    })
    .UseDefaultServiceProvider((_, options) =>
    {
        options.ValidateScopes = true;
        options.ValidateOnBuild = true;
    })
    .Build();

host.Run();
