namespace Cod.Platform.Identity.API
{
    public class LoginResult
    {
        public Guid? Tenant { get; set; }

        public Guid? User { get; set; }

        public AuthenticationKind? Challenge { get; set; }
    }
}
