using Niobium.Identity;
using System.Text;

namespace Niobium.Platform.Identity.API
{
    internal abstract class TOTPLoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository)
        : LoginRequestHandler(loginRepository, userRepository), ILoginRequestHandler
    {
        public const int TOTPValidityMinutes = 10;
        public static readonly TimeSpan TOTPValidity = TimeSpan.FromMinutes(TOTPValidityMinutes);

        public override bool CanHandle(string scheme, string identity, string? credential)
        {
            if (!base.CanHandle(scheme, identity, credential))
            {
                return false;
            }

            if (!string.Equals(scheme, AuthenticationScheme.BasicLoginScheme, StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            if (!IdentityHelper.TryParseAppAndUserName(identity, out _, out _))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(credential))
            {
                if (!IdentityHelper.TryParseTOTP(credential, out _))
                {
                    return false;
                }
            }

            return true;
        }

        public override async Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string? clientIP)
        {
            if (!CanHandle(scheme, identity, credential))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            if (!IdentityHelper.TryParseAppAndUserName(identity, out var app, out var username))
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            var kind = DetermineAuthenticationKind(scheme, app, username);
            if (kind == AuthenticationKind.Unknown)
            {
                throw new ApplicationException(Niobium.InternalError.BadRequest);
            }

            LoginResult result = new();
            Login? login = await LoginRepository.RetrieveAsync(Login.BuildPartitionKey(kind, app.ToKey()), Login.BuildRowKey(username));
            if (string.IsNullOrEmpty(credential))
            {
                var successSetup = await SetupTOTPAsync(kind, app, username, login, clientIP);
                if (successSetup)
                {
                    result.Challenge = kind;
                    result.ChallengeSubject = $"{app}|{username}";
                }
                else
                {
                    result.Challenge = AuthenticationKind.Authenticator;
                }

                return result;
            }

            if (login == null)
            {
                throw new ApplicationException(Niobium.InternalError.AuthenticationRequired);
            }

            if (!TryParseTOTPFromRecord(login, out var totp1, out var createdAt)
                || !IdentityHelper.TryParseTOTP(credential, out var totp2)
                || totp1 != totp2
                || !CheckTOTPValidity(createdAt))
            {
                throw new ApplicationException(Niobium.InternalError.AuthenticationRequired);
            }

            result.User = login.User;
            result.App = app;
            return result;
        }

        protected virtual async Task<bool> SetupTOTPAsync(AuthenticationKind kind, Guid app, string username, Login? login, string? clientIP)
        {
            var totp = NewTOTPRecord();
            var credential = IdentityHelper.BuildTOTPCredential(totp);
            var result = false;
            if (login == null)
            {
                await SetupNewLoginAsync(kind, app, username, credential, clientIP);
                await ChallengeAsync(kind, app, username, CredentialKind.TOTP, totp, clientIP);
                result = true;
            }
            else
            {
                if (login.Credentials == null || login.Credentials.StartsWith(IdentityHelper.TOTPCredentialPrefix))
                {
                    if (TryParseTOTPFromRecord(login, out var existingTOTP, out var existingTOTPCreatedAt) && CheckTOTPValidity(existingTOTPCreatedAt))
                    {
                        totp = NewTOTPRecord(existingTOTP);
                        credential = IdentityHelper.BuildTOTPCredential(totp);
                    }

                    login.Credentials = credential;
                    await LoginRepository.UpdateAsync(login);
                    result = true;
                }
            }

            if (result)
            {
                await ChallengeAsync(kind, app, username, CredentialKind.TOTP, totp, clientIP);
            }
            return result;
        }

        protected abstract AuthenticationKind DetermineAuthenticationKind(string scheme, Guid app, string username);

        protected abstract Task ChallengeAsync(AuthenticationKind kind, Guid app, string username, CredentialKind credentialKind, string credential, string? clientIP);

        protected static bool TryParseTOTPFromRecord(Login login, out string totp, out DateTimeOffset createdAt)
        {
            totp = string.Empty;
            createdAt = default;

            if (login.Credentials == null)
            {
                return false;
            }

            var parts = login.Credentials.Split(IdentityHelper.TOTPCredentialSplit);
            if (parts.Length != 2
                || parts[0] != IdentityHelper.TOTPCredentialPrefix
                || !TryParseTOTPFromTOTPCredential(parts[1], out totp, out createdAt)
                || !totp.All(char.IsDigit))
            {
                return false;
            }

            return true;
        }

        protected static string NewTOTPRecord(string? totp = null)
        {
            var now = DateTimeOffset.UtcNow;

            if (!string.IsNullOrWhiteSpace(totp) && totp.Length == IdentityHelper.TOTPLength && totp.All(char.IsDigit))
            {
                return $"{totp}@{now:o}";
            }

            var random = new Random(now.Microsecond);
            var digits = new StringBuilder(IdentityHelper.TOTPLength);
            for (int i = 0; i < IdentityHelper.TOTPLength; i++)
            {
                digits.Append(random.Next(9));
            }

            return $"{digits}@{now:o}";
        }

        private static bool TryParseTOTPFromTOTPCredential(string totpCredential, out string totp, out DateTimeOffset createdAt)
        {
            totp = string.Empty;
            createdAt = default;
            var parts = totpCredential.Split('@');
            if (parts.Length != 2 || !DateTimeOffset.TryParse(parts[1], out createdAt))
            {
                return false;
            }

            totp = parts[0];
            return totp.Length == IdentityHelper.TOTPLength && totp.All(char.IsDigit);
        }

        private static bool CheckTOTPValidity(DateTimeOffset createdAt) => DateTimeOffset.UtcNow - createdAt <= TOTPValidity;
    }
}
