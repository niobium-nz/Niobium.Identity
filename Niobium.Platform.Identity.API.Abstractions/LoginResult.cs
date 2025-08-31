using Niobium.Identity;

namespace Niobium.Platform.Identity.API
{
    public class LoginResult
    {
        public Guid? App { get; set; }

        public Guid? User { get; set; }

        public AuthenticationKind? Challenge { get; set; }

        public string? ChallengeSubject { get; set; }
    }
}
