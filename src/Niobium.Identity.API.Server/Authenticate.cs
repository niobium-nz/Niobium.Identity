using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Niobium.Identity.API.Server
{
    public class Authenticate(IAuthenticator authenticator)
    {
        [Function(nameof(Authenticate))]
        public async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = Constants.DefaultIDTokenEndpoint)]
            HttpRequest req,
            CancellationToken cancellationToken) => await authenticator.AuthenticateAsync(req, cancellationToken);
    }
}
