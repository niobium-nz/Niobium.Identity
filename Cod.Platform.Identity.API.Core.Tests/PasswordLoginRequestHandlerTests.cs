using FluentAssertions;
using Moq;

namespace Cod.Platform.Identity.API.Core.Tests
{
    [TestClass]
    public class PasswordLoginRequestHandlerTests
    {
        private readonly PasswordLoginRequestHandler subject;
        private readonly Mock<IRepository<Login>> repositoryMock;
        private readonly Mock<IConfigurationProvider> configurationMock;

        public PasswordLoginRequestHandlerTests()
        {
            repositoryMock = new Mock<IRepository<Login>>(MockBehavior.Strict);
            configurationMock = new Mock<IConfigurationProvider>(MockBehavior.Strict);
            configurationMock.Setup(x => x.GetSettingAsStringAsync(PasswordLoginRequestHandler.SETTING_PASSWORD_HASH_KEY, It.IsAny<bool>()))
                .ReturnsAsync("abcdefghijklmnopqrstuvwxyz0123456789");
            subject = new PasswordLoginRequestHandler(new Lazy<IRepository<Login>>(() => repositoryMock.Object), configurationMock.Object);
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
        [DataTestMethod]
        public async Task HandleAsync_BadRequest_ThrowsException(string scheme, string identity, string? credential)
        {
            // Act
            var act = async () => await subject.HandleAsync(scheme, identity, credential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.BadRequest);
        }

        [TestMethod]
        public async Task HandleAsync_LoginNotFound_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName";
            var validCredential = "123456";

            repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<Login>(null!));

            // Act
            var act = async () => await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{validCredential}", "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CredentialNotMatch_ThrowsAuthenticationRequiredException()
        {
            // Arrange
            var cred = "123456";
            var randomHash = "xxxxxxxxxxxxxxxx0000000";
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = randomHash,
                User = Guid.NewGuid(),
            };

            repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            var act = async () => await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{cred}", "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.AuthenticationRequired);
        }

        [TestMethod]
        public async Task HandleAsync_CorrectCredential_ReturnsUserIDWithoutChallenge()
        {
            // Arrange
            var cred = "123456";
            var expectedCredHash = "681915bd964f6d6431c007d818c070419f420695fa254b1cb7d4b9b8747bdca7";
            var basicAuthScheme = AuthenticationScheme.BasicLoginScheme;
            var validAppID = Guid.NewGuid();
            var validEmailAsUsername = "validUserName";
            Login existingLogin = new()
            {
                PartitionKey = Login.BuildPartitionKey(AuthenticationKind.Email, validAppID.ToKey()),
                RowKey = Login.BuildRowKey(validEmailAsUsername),
                Credentials = expectedCredHash,
                User = Guid.NewGuid(),
            };
            repositoryMock.Setup(x => x.RetrieveAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<IList<string>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(existingLogin);

            // Act
            var actual = await subject.HandleAsync(basicAuthScheme, $"{validAppID}|{validEmailAsUsername}", $"{PasswordLoginRequestHandler.PASSWORD_LOGIN_CREDENTIAL_PREFIX}{cred}", "192.168.123.123");

            // Assert
            actual.User.Should().Be(existingLogin.User);
            actual.Challenge.HasValue.Should().BeFalse();
            repositoryMock.Verify();
        }
    }
}
