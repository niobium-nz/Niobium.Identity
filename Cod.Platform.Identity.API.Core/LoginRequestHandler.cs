namespace Cod.Platform.Identity.API
{
    internal abstract class LoginRequestHandler(Lazy<IRepository<Login>> loginRepository, Lazy<IRepository<User>> userRepository) : ILoginRequestHandler
    {
        protected IRepository<Login> LoginRepository { get => loginRepository.Value; }
        protected IRepository<User> UserRepository { get => userRepository.Value; }

        public virtual bool CanHandle(string scheme, string identity, string? credential)
          => !string.IsNullOrWhiteSpace(identity);

        public abstract Task<LoginResult> HandleAsync(string scheme, string identity, string? credential, string clientIP);

        protected async Task<Guid> SetupNewLoginAsync(AuthenticationKind channel, Guid app, string openID, string? credential, string clientIP)
        {
            var userID = Guid.NewGuid();

            await UserRepository.CreateAsync(new User
            {
                Prefix = User.BuildPartitionKey(userID),
                ID = userID,
                FirstIP = clientIP,
                LastIP = clientIP,
            });

            await LoginRepository.CreateAsync(new Login
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
