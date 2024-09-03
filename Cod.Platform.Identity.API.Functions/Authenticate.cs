using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Cod.Platform.Identity.API.Functions
{
    public class Authenticate(IAuthenticator authenticator)
    {
        [Function(nameof(Authenticate))]
        public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = Uris.Authenticate)] HttpRequest req, CancellationToken cancellationToken)
            => await authenticator.AuthenticateAsync(req, cancellationToken);
    }
}
