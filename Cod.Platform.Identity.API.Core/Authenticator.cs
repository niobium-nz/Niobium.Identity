using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace Cod.Platform.Identity.API
{
    internal class Authenticator(Lazy<IDomainRepository<AuthenticationDomain, User>> repository, IEnumerable<ILoginRequestHandler> loginRequestHandlers) : IAuthenticator
    {
        public async Task<IActionResult> AuthenticateAsync(HttpRequest req, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(req);
            if (!req.TryGetAuthorizationCredentials(out string scheme, out string identity, out string? credential))
            {
                return new BadRequestResult();
            }

            var loginRequestHandler = loginRequestHandlers.SingleOrDefault(h => h.CanHandle(scheme, identity, credential));
            if (loginRequestHandler == null)
            {
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
            }

            var clientIP = req.GetRemoteIP();
            var loginResult = await loginRequestHandler.HandleAsync(scheme, identity, credential, clientIP);
            if (loginResult.Challenge != null)
            {
                req.DeliverAuthenticationToken(null, loginResult.Challenge.ToString());
                return new UnauthorizedResult();
            }

            if (loginResult.User.HasValue && loginResult.Tenant.HasValue)
            {
                var domain = await repository.Value.GetAsync(User.BuildPartitionKey(loginResult.User.Value), User.BuildRowKey(loginResult.User.Value), cancellationToken);
                var token = await domain.IssueTokenAsync(loginResult.Tenant.Value);
                req.DeliverAuthenticationToken(token, AuthenticationScheme.BearerLoginScheme);
                await AuditLoginAsync(loginResult.User.Value, clientIP);
                return new OkResult();
            }

            return new UnauthorizedResult();
        }

        private async Task AuditLoginAsync(Guid userID, string? clientIP)
        {
            if (clientIP == null)
            {
                return;
            }

            var user = await repository.Value.GetAsync(User.BuildPartitionKey(userID), User.BuildRowKey(userID));
            await user.AuditAsync(clientIP);
        }
    }
}
