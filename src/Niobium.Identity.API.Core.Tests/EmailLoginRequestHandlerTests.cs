using FluentAssertions;
using Moq;
using Moq.Protected;

namespace Niobium.Identity.API.Core.Tests
{
    [TestClass]
    public class EmailLoginRequestHandlerTests
    {
        private readonly EmailLoginRequestHandler subject;
        private readonly Mock<EmailLoginRequestHandler> mock;
        private readonly Mock<IRepository<Login>> loginRepositoryMock;
        private readonly Mock<IRepository<User>> userRepositoryMock;

        public EmailLoginRequestHandlerTests()
        {
            this.loginRepositoryMock = new Mock<IRepository<Login>>(MockBehavior.Strict);
            this.userRepositoryMock = new Mock<IRepository<User>>(MockBehavior.Strict);
            this.mock = new Mock<EmailLoginRequestHandler>(
                new Lazy<IRepository<Login>>(() => this.loginRepositoryMock.Object),
                new Lazy<IRepository<User>>(() => this.userRepositoryMock.Object))
            {
                CallBase = true,
            };
            this.subject = this.mock.Object;
        }

        [DataRow(AuthenticationScheme.BearerLoginScheme, "anything", "anything")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "anything", "anything")]
        [DataRow("AnythingOtherThanBasic", "anything", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "AnythingMissingSpliter", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "NonGuidWithSpliter|xxx", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|MoreThan1Spliter|xxx", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "|validUserName@gmail.com", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "|123456")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "AnythingMissingSpliter")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "TOTP|MoreThan1Spliter|xxx")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "TOTP|")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "TOTP|AnythingOtherThan6Digits")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName@gmail.com", "AnythingOtherThanTOTP|123456")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|invalidUserName", "TOTP|123456")]
        [TestMethod]
        public async Task HandleAsync_BadRequest_ThrowsException(string scheme, string identity, string? credential)
        {
            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(scheme, identity, credential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.BadRequest);
        }

        [TestMethod]
        public async Task HandleAsync_FirstTimeLogin_CreateNewLogin()
        {
            // Arrange
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string emptyCredential = String.Empty;
            IEnumerable<Login> actualLoginsCreated = [];
            IEnumerable<User> actualUsersCreated = [];
            this.loginRepositoryMock.Setup(x => x.CreateAsync(It.IsAny<IEnumerable<Login>>(), It.IsAny<bool>(), It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<Login>, bool, DateTimeOffset?, CancellationToken>((logins, _, _, _) => actualLoginsCreated = logins)
                .ReturnsAsync(() => actualLoginsCreated);
            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login?>(null!));
            this.userRepositoryMock.Setup(x => x.CreateAsync(It.IsAny<IEnumerable<User>>(), It.IsAny<bool>(), It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<User>, bool, DateTimeOffset?, CancellationToken>((users, _, _, _) => actualUsersCreated = users)
                .ReturnsAsync(() => actualUsersCreated);
            this.mock.Protected().Setup<Task>("ChallengeAsync", ItExpr.IsAny<AuthenticationKind>(), ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>(), ItExpr.IsAny<CredentialKind>(), ItExpr.IsAny<string>(), ItExpr.IsAny<string>())
                .Returns(Task.CompletedTask)
                .Verifiable();

            // Act
            LoginResult actual = await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", emptyCredential, "192.168.123.123");

            // Assert
            actual.User.Should().BeNull();
            actual.Challenge!.Value.Should().Be(AuthenticationKind.Email);
            actual.ChallengeSubject.Should().Be($"{validAppID}|{validEmailAsUsername}");
            actualLoginsCreated.Single().PartitionKey.Should().Be($"{(int)AuthenticationKind.Email}|{validAppID}");
            actualLoginsCreated.Single().RowKey.Should().StartWith(validEmailAsUsername);
            actualLoginsCreated.Single().Credentials.Should().StartWith($"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}");
            this.loginRepositoryMock.Verify();
            this.userRepositoryMock.Verify();
            actualLoginsCreated.Single().User.Should().Be(actualUsersCreated.Single().ID);
            this.mock.Verify();
        }

        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes - 1, false)]
        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes, true)]
        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes + 1, true)]
        [TestMethod]
        public async Task HandleAsync_NonFirstTimeLogin_OverrideExistingLogin(int loginTimeDifferenceInMinutes, bool shouldRenewTOTP)
        {
            // Arrange
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string emptyCredential = String.Empty;
            IEnumerable<Login> actualLoginsUpdated = [];
            DateTimeOffset now = DateTimeOffset.Now;
            DateTimeOffset lastLoginTime = now.AddMinutes(-loginTimeDifferenceInMinutes);
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}123456@{lastLoginTime:o}",
                User = Guid.NewGuid(),
            };
            this.loginRepositoryMock.Setup(x => x.UpdateAsync(It.IsAny<IEnumerable<Login>>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<Login>, bool, bool, CancellationToken>((logins, _, _, _) => actualLoginsUpdated = logins)
                .ReturnsAsync(() => actualLoginsUpdated);
            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);
            this.mock.Protected().Setup<Task>("ChallengeAsync", ItExpr.IsAny<AuthenticationKind>(), ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>(), ItExpr.IsAny<CredentialKind>(), ItExpr.IsAny<string>(), ItExpr.IsAny<string>())
                .Returns(Task.CompletedTask)
                .Verifiable();

            // Act
            LoginResult actual = await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", emptyCredential, "192.168.123.123");

            // Assert
            actual.User.Should().BeNull();
            actual.Challenge!.Value.Should().Be(AuthenticationKind.Email);
            actual.ChallengeSubject.Should().Be($"{validAppID}|{validEmailAsUsername}");
            actualLoginsUpdated.Single().PartitionKey.Should().Be(existingLogin.PartitionKey);
            actualLoginsUpdated.Single().RowKey.Should().Be(existingLogin.RowKey);
            actualLoginsUpdated.Single().User.Should().Be(existingLogin.User);

            if (shouldRenewTOTP)
            {
                actualLoginsUpdated.Single().Credentials.Should().NotStartWith($"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}123456@");
            }
            else
            {
                actualLoginsUpdated.Single().Credentials.Should().StartWith($"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}123456@");
            }

            this.loginRepositoryMock.Verify();
            this.mock.Verify();
        }

        [TestMethod]
        public async Task HandleAsync_LoginNotFound_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string validCredential = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}123456";

            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login?>(null!));

            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", validCredential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_TOTPNotMatch_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            string totp1 = "123456";
            string totp2 = "654321";
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string validCredential = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp1}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp2}@{DateTimeOffset.Now:o}",
                User = Guid.NewGuid(),
            };

            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", validCredential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_TOTPExpired_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            string totp = "123456";
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string credentialSubmitting = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp}";
            string expiredGeneratedCredential = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp}@{DateTimeOffset.UtcNow.Add(-TOTPLoginRequestHandler.TOTPValidity).AddSeconds(-1):o}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = expiredGeneratedCredential,
                User = Guid.NewGuid(),
            };

            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", credentialSubmitting, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CorrectCredential_ReturnsUserIDWithoutChallenge()
        {
            // Arrange
            string totp = "123456";
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName@gmail.com";
            string correctCredential = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{IdentityHelper.TOTPCredentialPrefix}{IdentityHelper.TOTPCredentialSplit}{totp}@{DateTimeOffset.Now:o}",
                User = Guid.NewGuid(),
            };
            this.loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            LoginResult actual = await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", correctCredential, "192.168.123.123");

            // Assert
            actual.User.Should().Be(existingLogin.User);
            actual.Challenge.HasValue.Should().BeFalse();
            this.loginRepositoryMock.Verify();
        }
    }
}
