using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Hosting;
using Niobium.Identity.API.Server;

FunctionsApplication.CreateBuilder(args)
    .ConfigureFunctionsWebApplication()
    .AddIdentityAPI()
    .UseIdentityAPI()
    .Build()
    .Run();
