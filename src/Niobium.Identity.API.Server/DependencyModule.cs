using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Hosting;
using Niobium.Platform;
using Niobium.Platform.Functions;

namespace Niobium.Identity.API.Server
{
    internal static class DependencyModule
    {
        private static volatile bool added;
        private static volatile bool used;

        public static TBuilder AddIdentityAPI<TBuilder>(this TBuilder builder)
             where TBuilder : IHostApplicationBuilder
        {
            if (added)
            {
                return builder;
            }

            added = true;

            Platform.Functions.DependencyModule.AddPlatform(builder);
            builder.AddCore();
            return builder;
        }

        public static TBuilder UseIdentityAPI<TBuilder>(this TBuilder builder) where TBuilder : IFunctionsWorkerApplicationBuilder
        {
            if (used)
            {
                return builder;
            }

            used = true;

            builder.ToMiddlewareHost().UsePlatform();
            return builder;
        }
    }
}
