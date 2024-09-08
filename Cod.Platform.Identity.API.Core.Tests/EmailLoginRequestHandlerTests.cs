using FluentAssertions;
using Moq;
using Moq.Protected;

namespace Cod.Platform.Identity.API.Core.Tests
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
            loginRepositoryMock = new Mock<IRepository<Login>>(MockBehavior.Strict);
            userRepositoryMock = new Mock<IRepository<User>>(MockBehavior.Strict);
            mock = new Mock<EmailLoginRequestHandler>(
                new Lazy<IRepository<Login>>(() => loginRepositoryMock.Object),
                new Lazy<IRepository<User>>(() => userRepositoryMock.Object))
            {
                CallBase = true,
            };
            subject = mock.Object;
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
        [DataTestMethod]
        public async Task HandleAsync_BadRequest_ThrowsException(string scheme, string identity, string? credential)
        {
            // Act
            var act = async () => await subject.HandleAsync(scheme, identity, credential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.BadRequest);
        }

        [TestMethod]
        public async Task HandleAsync_FirstTimeLogin_CreateNewLogin()
        {
            // Arrange
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var emptyCredential = string.Empty;
            IEnumerable<Login> actualLoginsCreated = [];
            IEnumerable<User> actualUsersCreated = [];
            loginRepositoryMock.Setup(x => x.CreateAsync(It.IsAny<IEnumerable<Login>>(), It.IsAny<bool>(), It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<Login>, bool, DateTimeOffset?, CancellationToken>((logins, _, _, _) => actualLoginsCreated = logins)
                .ReturnsAsync(() => actualLoginsCreated);
            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login>(null!));
            userRepositoryMock.Setup(x => x.CreateAsync(It.IsAny<IEnumerable<User>>(), It.IsAny<bool>(), It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<User>, bool, DateTimeOffset?, CancellationToken>((users, _, _, _) => actualUsersCreated = users)
                .ReturnsAsync(() => actualUsersCreated);
            mock.Protected().Setup<Task>("ChallengeAsync", ItExpr.IsAny<AuthenticationKind>(), ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>(), ItExpr.IsAny<CredentialKind>(), ItExpr.IsAny<string>(), ItExpr.IsAny<string>())
                .Returns(Task.CompletedTask)
                .Verifiable();

            // Act
            var actual = await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", emptyCredential, "192.168.123.123");

            // Assert
            actual.User.Should().BeNull();
            actual.Challenge!.Value.Should().Be(AuthenticationKind.Email);
            actual.ChallengeSubject.Should().Be(validEmailAsUsername);
            actualLoginsCreated.Single().PartitionKey.Should().Be($"{(int)AuthenticationKind.Email}|{validAppID}");
            actualLoginsCreated.Single().RowKey.Should().StartWith(validEmailAsUsername);
            actualLoginsCreated.Single().Credentials.Should().StartWith($"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}");
            loginRepositoryMock.Verify();
            userRepositoryMock.Verify();
            actualLoginsCreated.Single().User.Should().Be(Guid.Parse(actualUsersCreated.Single().RowKey));
            mock.Verify();
        }

        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes - 1, false)]
        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes, true)]
        [DataRow(TOTPLoginRequestHandler.TOTPValidityMinutes + 1, true)]
        [DataTestMethod]
        public async Task HandleAsync_NonFirstTimeLogin_OverrideExistingLogin(int loginTimeDifferenceInMinutes, bool shouldRenewTOTP)
        {
            // Arrange
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var emptyCredential = string.Empty;
            IEnumerable<Login> actualLoginsUpdated = [];
            var now = DateTimeOffset.Now;
            var lastLoginTime = now.AddMinutes(-loginTimeDifferenceInMinutes);
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}123456@{lastLoginTime:o}",
                User = Guid.NewGuid(),
            };
            loginRepositoryMock.Setup(x => x.UpdateAsync(It.IsAny<IEnumerable<Login>>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
                .Callback<IEnumerable<Login>, bool, CancellationToken>((logins, _, _) => actualLoginsUpdated = logins)
                .ReturnsAsync(() => actualLoginsUpdated);
            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);
            mock.Protected().Setup<Task>("ChallengeAsync", ItExpr.IsAny<AuthenticationKind>(), ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>(), ItExpr.IsAny<CredentialKind>(), ItExpr.IsAny<string>(), ItExpr.IsAny<string>())
                .Returns(Task.CompletedTask)
                .Verifiable();

            // Act
            var actual = await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", emptyCredential, "192.168.123.123");

            // Assert
            actual.User.Should().BeNull();
            actual.Challenge!.Value.Should().Be(AuthenticationKind.Email);
            actual.ChallengeSubject.Should().Be(validEmailAsUsername);
            actualLoginsUpdated.Single().PartitionKey.Should().Be(existingLogin.PartitionKey);
            actualLoginsUpdated.Single().RowKey.Should().Be(existingLogin.RowKey);
            actualLoginsUpdated.Single().User.Should().Be(existingLogin.User);

            if (shouldRenewTOTP)
            {
                actualLoginsUpdated.Single().Credentials.Should().NotStartWith($"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}123456@");
            }
            else
            {
                actualLoginsUpdated.Single().Credentials.Should().StartWith($"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}123456@");
            }

            loginRepositoryMock.Verify();
            mock.Verify();
        }

        [TestMethod]
        public async Task HandleAsync_LoginNotFound_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var validCredential = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}123456";

            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login>(null!));

            // Act
            var act = async () => await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", validCredential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_TOTPNotMatch_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            var totp1 = "123456";
            var totp2 = "654321";
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var validCredential = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp1}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp2}@{DateTimeOffset.Now:o}",
                User = Guid.NewGuid(),
            };

            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            var act = async () => await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", validCredential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_TOTPExpired_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            var totp = "123456";
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var credentialSubmitting = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp}";
            var expiredGeneratedCredential = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp}@{DateTimeOffset.UtcNow.Add(-TOTPLoginRequestHandler.TOTPValidity).AddSeconds(-1):o}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = expiredGeneratedCredential,
                User = Guid.NewGuid(),
            };

            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            var act = async () => await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", credentialSubmitting, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CorrectCredential_ReturnsUserIDWithoutChallenge()
        {
            // Arrange
            var totp = "123456";
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName@gmail.com";
            var correctCredential = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp}";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = $"{EmailLoginRequestHandler.TOTPCredentialPrefix}{EmailLoginRequestHandler.TOTPCredentialSplit}{totp}@{DateTimeOffset.Now:o}",
                User = Guid.NewGuid(),
            };
            loginRepositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            var actual = await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", correctCredential, "192.168.123.123");

            // Assert
            actual.User.Should().Be(existingLogin.User);
            actual.Challenge.HasValue.Should().BeFalse();
            loginRepositoryMock.Verify();
        }
    }
}
