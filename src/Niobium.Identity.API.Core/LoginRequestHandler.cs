namespace Niobium.Identity.API
{
    internal abstract class LoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository) : ILoginRequestHandler
    {
        protected IRepository<Login> LoginRepository => loginRepository.Value;
        protected IRepository<User> UserRepository => userRepository.Value;

        public virtual bool CanHandle(string scheme, string identity, string? credential)
          => !String.IsNullOrWhiteSpace(identity);

        public abstract Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string? clientIP);

        protected async Task<Guid> SetupNewLoginAsync(AuthenticationKind channel, Guid app, string openID, string? credential, string? clientIP)
        {
            Guid userID = Guid.NewGuid();

            await this.UserRepository.CreateAsync(new User
            {
                Prefix = User.BuildPartitionKey(userID),
                ID = userID,
                FirstIP = clientIP,
                LastIP = clientIP,
            });

            await this.LoginRepository.CreateAsync(new Login
            {
                PartitionKey = Login.BuildPartitionKey(channel, app.ToKey()),
                RowKey = Login.BuildRowKey(openID),
                User = userID,
                Credentials = credential,
            });

            return userID;
        }
    }
}
