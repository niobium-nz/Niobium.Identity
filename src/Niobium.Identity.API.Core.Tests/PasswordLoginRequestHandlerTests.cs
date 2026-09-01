using FluentAssertions;
using Moq;

namespace Niobium.Identity.API.Core.Tests
{
    [TestClass]
    public class PasswordLoginRequestHandlerTests
    {
        private readonly PasswordLoginRequestHandler subject;
        private readonly Mock<IRepository<Login>> repositoryMock;
        private readonly Mock<IConfigurationProvider> configurationMock;

        public PasswordLoginRequestHandlerTests()
        {
            this.repositoryMock = new Mock<IRepository<Login>>(MockBehavior.Strict);
            this.configurationMock = new Mock<IConfigurationProvider>(MockBehavior.Strict);
            this.configurationMock.Setup(x => x.GetSettingAsStringAsync(PasswordLoginRequestHandler.SETTING_PASSWORD_HASH_KEY, It.IsAny<bool>()))
                .ReturnsAsync("abcdefghijklmnopqrstuvwxyz0123456789");
            this.subject = new PasswordLoginRequestHandler(new Lazy<IRepository<Login>>(() => this.repositoryMock.Object), this.configurationMock.Object);
        }

        [DataRow(AuthenticationScheme.BearerLoginScheme, "anything", "anything")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "anything", "anything")]
        [DataRow("AnythingOtherThanBasic", "anything", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "AnythingMissingSpliter", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "NonGuidWithSpliter|xxx", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|MoreThan1Spliter|xxx", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "|validUserName", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName", "")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494|validUserName", "anythingNotExpected:123456")]
        [TestMethod]
        public async Task HandleAsync_BadRequest_ThrowsException(string scheme, string identity, string? credential)
        {
            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(scheme, identity, credential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.BadRequest);
        }

        [TestMethod]
        public async Task HandleAsync_LoginNotFound_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName";
            string validCredential = "123456";

            this.repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login?>(null!));

            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{validCredential}", "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CredentialNotMatch_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            string cred = "123456";
            string randomHash = "xxxxxxxxxxxxxxxx0000000";
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = randomHash,
                User = Guid.NewGuid(),
            };

            this.repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            Func<Task<LoginResult>> act = async () => await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{cred}", "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == Niobium.InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CorrectCredential_ReturnsUserIDWithoutChallenge()
        {
            // Arrange
            string cred = "123456";
            string expectedCredHash = "681915bd964f6d6431c007d818c070419f420695fa254b1cb7d4b9b8747bdca7";
            string basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            string validEmailAsUsername = "validUserName";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = expectedCredHash,
                User = Guid.NewGuid(),
            };
            this.repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            LoginResult actual = await this.subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{cred}", "192.168.123.123");

            // Assert
            actual.User.Should().Be(existingLogin.User);
            actual.Challenge.HasValue.Should().BeFalse();
            this.repositoryMock.Verify();
        }
    }
}
