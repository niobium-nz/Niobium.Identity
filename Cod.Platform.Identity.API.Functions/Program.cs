using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Cod.Platform.Identity.API;
using Functions.Worker.ContextAccessor;

IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureFunctionsWebApplication(builder =>
    {
        builder.UseFunctionContextAccessor();
    })
    .ConfigureServices((hostContext, services) =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();

        services.AddFunctionContextAccessor();
        services.AddTransient(sp =>
        {
            var functionContext = sp.GetRequiredService<IFunctionContextAccessor>().FunctionContext;
            return functionContext.GetLogger(functionContext.FunctionDefinition.Name);
        });

        services.AddCodIdentityAPI(hostContext.Configuration);
    })
    .UseDefaultServiceProvider((_, options) =>
    {
        options.ValidateScopes = true;
        options.ValidateOnBuild = true;
    })
    .Build();

host.Run();
