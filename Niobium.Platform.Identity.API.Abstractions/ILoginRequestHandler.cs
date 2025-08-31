namespace Niobium.Platform.Identity.API
{
    public interface ILoginRequestHandler
    {
        bool CanHandle(string scheme, string identity, string? credential);

        Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string? clientIP);
    }
}
