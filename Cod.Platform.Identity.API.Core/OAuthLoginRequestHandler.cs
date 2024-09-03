namespace Cod.Platform.Identity.API
{
    internal abstract class OAuthLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : LoginRequestHandler(loginRepository, userRepository), ILoginRequestHandler
    {
        public override bool CanHandle(string scheme, string identity, string? credential)
        {
            return base.CanHandle(scheme, identity, credential)
                && string.Equals(scheme, AuthenticationScheme.OAuthLoginScheme, StringComparison.InvariantCultureIgnoreCase)
                && !string.IsNullOrEmpty(credential);
        }

        public override async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string clientIP)
        {
            if (!CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            if (!TryParseOAuthParameters(identity, credential, out var channel, out var tenantID, out var authCode))
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            if (channel == AuthenticationKind.Unknown)
            {
                throw new ApplicationException(InternalError.BadRequest);
            }

            var openID = await GetOpenIDAsync(tenantID, authCode);
            if (string.IsNullOrWhiteSpace(openID))
            {
                throw new ApplicationException(InternalError.InternalServerError);
            }

            Login login = await LoginRepository.RetrieveAsync(Login.BuildPartitionKey(channel, tenantID.ToKey()), Login.BuildRowKey(openID));
            Guid userID = login?.User ?? await SetupNewLoginAsync(channel, tenantID, openID, null, clientIP);

            return new()
            {
                User = userID,
                Tenant = tenantID,
            };
        }

        protected virtual bool TryParseOAuthParameters(string identity, string? credential,
            out AuthenticationKind kind, out Guid tenantID, out string authCode)
        {
            kind = AuthenticationKind.Unknown;
            authCode = string.Empty;
            if (!Guid.TryParse(identity, out tenantID) || credential == null)
            {
                return false;
            }

            var parts = credential.Split('@');
            if (parts.Length == 2
                && Enum.TryParse(parts[0], out kind)
                && !string.IsNullOrWhiteSpace(parts[1]))
            {
                authCode = parts[1];
                return true;
            }

            return false;
        }

        protected abstract Task<string?> GetOpenIDAsync(Guid tenantID, string authCode);
    }
}
