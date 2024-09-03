namespace Cod.Platform.Identity.API
{
    internal class EmailLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : TOTPLoginRequestHandler(loginRepository, userRepository)
    {
        public override bool CanHandle(string scheme, string identity, string? credential)
        {
            return base.CanHandle(scheme, identity, credential)
                && IdentityHelper.TryParseTenantAndUserName(identity, out var tenantID, out var username)
                && DetermineAuthenticationKind(scheme, tenantID, username) == AuthenticationKind.Email;
        }

        protected override Task ChallengeAsync(AuthenticationKind kind, Guid tenantID, string username, CredentialKind credentialKind, string credential, string clientIP)
        {
            throw new NotImplementedException();
        }

        protected override AuthenticationKind DetermineAuthenticationKind(string scheme, Guid tenantID, string username)
        {
            if (RegexUtilities.IsValidEmail(username))
            {
                return AuthenticationKind.Email;
            }

            return AuthenticationKind.Unknown;
        }
    }
}
