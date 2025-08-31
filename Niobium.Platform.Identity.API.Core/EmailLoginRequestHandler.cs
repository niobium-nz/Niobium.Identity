using Niobium.Identity;

namespace Niobium.Platform.Identity.API
{
    internal class EmailLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : TOTPLoginRequestHandler(loginRepository, userRepository)
    {
        public override bool CanHandle(string scheme, string identity, string? credential)
        {
            return base.CanHandle(scheme, identity, credential)
                && IdentityHelper.TryParseAppAndUserName(identity, out var app, out var username)
                && DetermineAuthenticationKind(scheme, app, username) == AuthenticationKind.Email;
        }

        protected override Task ChallengeAsync(AuthenticationKind kind, Guid app, string username, CredentialKind credentialKind, string credential, string? clientIP)
        {
            return Task.CompletedTask;
        }

        protected override AuthenticationKind DetermineAuthenticationKind(string scheme, Guid app, string username)
        {
            if (RegexUtilities.IsValidEmail(username))
            {
                return AuthenticationKind.Email;
            }

            return AuthenticationKind.Unknown;
        }
    }
}
