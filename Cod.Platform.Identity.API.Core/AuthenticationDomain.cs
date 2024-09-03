using Cod.Platform.Identity.Authentication;

namespace Cod.Platform.Identity.API
{
    internal class AuthenticationDomain(
        Lazy<IRepository<User>> repository,
        IEnumerable<IEventHandler<IDomain<User>>> eventHandlers,
        Lazy<ITokenBuilder> tokenBuilder)
        : GenericDomain<User>(repository, eventHandlers)
    {
        public async Task<string> IssueTokenAsync(Guid tenantID)
        {
            User entity = await GetEntityAsync() ?? throw new ApplicationException(InternalError.NotFound);
            if (entity.Disabled)
            {
                throw new ApplicationException(InternalError.Locked);
            }

            Guid userID = entity.GetID();
            return await tokenBuilder.Value.BuildAsync(userID.ToKey(), audience: tenantID.ToString());
        }

        public async Task AuditAsync(string clientIP)
        {
            User entity = await GetEntityAsync();
            if (entity != null)
            {
                entity.LastIP = clientIP;
            }

            await SaveAsync();
        }
    }
}
