namespace Niobium.Identity.API
{
    internal class EmailLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : TOTPLoginRequestHandler(loginRepository, userRepository)
    {
        public override bool CanHandle(string scheme, string identity, string? credential) => base.CanHandle(scheme, identity, credential)
                && IdentityHelper.TryParseAppAndUserName(identity, out Guid app, out string? username)
                && this.DetermineAuthenticationKind(scheme, app, username) == AuthenticationKind.Email;

        protected override Task ChallengeAsync(AuthenticationKind kind, Guid app, string username, CredentialKind credentialKind, string credential, string? clientIP) => Task.CompletedTask;

        protected override AuthenticationKind DetermineAuthenticationKind(string scheme, Guid app, string username) => RegexUtilities.IsValidEmail(username) ? AuthenticationKind.Email : AuthenticationKind.Unknown;
    }
}
