using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using System.Security.Claims;

namespace Cod.Platform.Identity.API.Functions
{
    public class Profile(PrincipalParser principalParser, IRepository<Dictionary<string, object>> repo)
    {
        private const string AudienceClaim = "aud";

        [Function(nameof(GetProfile))]
        public async Task<IActionResult> GetProfile([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = Cod.Identity.Constants.DefaultProfileEndpoint)] HttpRequest req, CancellationToken cancellationToken)
        {
            var principal = await principalParser.ParseIDPrincipalAsync(req, cancellationToken);
            if (principal == null)
            {
                return new UnauthorizedResult();
            }

            if (!principal.TryGetClaim<Guid>(ClaimTypes.NameIdentifier, out var user) || user == Guid.Empty)
            {
                return new ForbidResult();
            }

            if (!principal.TryGetClaim<Guid>(AudienceClaim, out var tenant) || tenant == Guid.Empty)
            {
                return new ForbidResult();
            }

            var profile = await repo.RetrieveAsync(tenant.ToString(), user.ToString(), cancellationToken: cancellationToken);

            if (profile == null)
            {
                return new NotFoundResult();
            }

            if (profile.TryGetValue(Cod.Database.StorageTable.Constants.AzureTableETagKey, out var etag))
            {
                profile.Add(nameof(EntityKeyKind.ETag), etag);
                profile.Remove(Cod.Database.StorageTable.Constants.AzureTableETagKey);
            }

            return new OkObjectResult(profile);
        }

        [Function(nameof(SetProfile))]
        public async Task<IActionResult> SetProfile([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = Cod.Identity.Constants.DefaultProfileEndpoint)] HttpRequest req, CancellationToken cancellationToken)
        {
            var principal = await principalParser.ParseIDPrincipalAsync(req, cancellationToken);
            if (principal == null)
            {
                return new UnauthorizedResult();
            }

            if (!principal.TryGetClaim<Guid>(ClaimTypes.NameIdentifier, out var user) || user == Guid.Empty)
            {
                return new ForbidResult();
            }

            if (!principal.TryGetClaim<Guid>(AudienceClaim, out var tenant) || tenant == Guid.Empty)
            {
                return new ForbidResult();
            }

            var profile = await req.ReadFromJsonAsync<Dictionary<string, object>>(cancellationToken: cancellationToken);
            if (profile == null || profile.Count == 0)
            {
                return new BadRequestResult();
            }

            profile.Remove(nameof(EntityKeyKind.PartitionKey));
            profile.Remove(nameof(EntityKeyKind.RowKey));
            profile.Remove(nameof(EntityKeyKind.Timestamp));
            profile.Add(nameof(EntityKeyKind.PartitionKey), tenant.ToString());
            profile.Add(nameof(EntityKeyKind.RowKey), user.ToString());

            var preconditionCheck = profile.ContainsKey(nameof(EntityKeyKind.ETag));
            await repo.UpdateAsync(profile, preconditionCheck: preconditionCheck, mergeIfExists: true, cancellationToken: cancellationToken);

            return new OkResult();
        }
    }
}
