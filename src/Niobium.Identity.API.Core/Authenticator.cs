using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Niobium.Platform;
using Niobium.Platform.Identity;

namespace Niobium.Identity.API
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

            ILoginRequestHandler? loginRequestHandler = loginRequestHandlers.SingleOrDefault(h => h.CanHandle(scheme, identity, credential));
            if (loginRequestHandler == null)
            {
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
            }

            string? clientIP = req.GetRemoteIP();
            LoginResult loginResult = await loginRequestHandler.HandleAsync(scheme, identity, credential, clientIP);
            if (loginResult.Challenge.HasValue)
            {
                string forbidScheme = loginResult.Challenge.Value.ToString();
                req.DeliverChallenge(loginResult.ChallengeSubject, forbidScheme);
                return new StatusCodeResult((int)HttpStatusCode.Forbidden);
            }

            if (loginResult.User.HasValue && loginResult.App.HasValue)
            {
                AuthenticationDomain domain = await repository.Value.GetAsync(User.BuildPartitionKey(loginResult.User.Value), User.BuildRowKey(loginResult.User.Value), cancellationToken: cancellationToken);
                string token = await domain.IssueTokenAsync(loginResult.App.Value);
                req.DeliverToken(token, AuthenticationScheme.BearerLoginScheme);
                await this.AuditLoginAsync(loginResult.User.Value, clientIP);
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

            AuthenticationDomain user = await repository.Value.GetAsync(User.BuildPartitionKey(userID), User.BuildRowKey(userID));
            await user.AuditAsync(clientIP);
        }
    }
}
