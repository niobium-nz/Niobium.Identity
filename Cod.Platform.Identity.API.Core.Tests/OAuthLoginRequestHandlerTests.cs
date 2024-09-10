using FluentAssertions;
using Moq;
using Moq.Protected;

namespace Cod.Platform.Identity.API.Core.Tests
{
    [TestClass]
    public class OAuthLoginRequestHandlerTests
    {
        private readonly OAuthLoginRequestHandler subject;
        private readonly Mock<OAuthLoginRequestHandler> mock;
        private readonly Mock<IRepository<Login>> loginRepositoryMock;
        private readonly Mock<IRepository<User>> userRepositoryMock;

        public OAuthLoginRequestHandlerTests()
        {
            loginRepositoryMock = new Mock<IRepository<Login>>(MockBehavior.Strict);
            userRepositoryMock = new Mock<IRepository<User>>(MockBehavior.Strict);
            mock = new Mock<OAuthLoginRequestHandler>(
                new Lazy<IRepository<Login>>(() => loginRepositoryMock.Object),
                new Lazy<IRepository<User>>(() => userRepositoryMock.Object))
            {
                CallBase = true,
            };
            subject = mock.Object;
        }

        [DataRow(AuthenticationScheme.BearerLoginScheme, "anything", "anything")]
        [DataRow(AuthenticationScheme.BasicLoginScheme, "anything", "anything")]
        [DataRow("AnythingOtherThanOAuth", "anything", "anything")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "", "anything")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494", "@123456")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494", "AnythingMissingSpliter")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494", "Wechat@MoreThan1Spliter@xxx")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494", "Wechat@")]
        [DataRow(AuthenticationScheme.OAuthLoginScheme, "95B52E52-DC79-4AC0-A53F-1ACB10238494", "SomethingInvalid@123456")]
        [DataTestMethod]
        public async Task HandleAsync_BadRequest_ThrowsException(string scheme, string identity, string? credential)
        {
            // Act
            var act = async () => await subject.HandleAsync(scheme, identity, credential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.BadRequest);
        }

        [DataRow(AuthenticationKind.Wechat)]
        [DataRow(AuthenticationKind.Alipay)]
        [DataRow(AuthenticationKind.Apple)]
        [DataRow(AuthenticationKind.Google)]
        [DataRow(AuthenticationKind.Microsoft)]
        [DataTestMethod]
        public async Task HandleAsync_FirstTimeLogin_CreateNewLogin(AuthenticationKind channel)
        {
            // Arrange
            var validAppID = Guid.NewGuid();
            var validCredential = $"{channel}@123456";
            var openID = "abcdefg";
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
            mock.Protected().Setup<Task<string?>>("GetOpenIDAsync", ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>())
                .Returns(Task.FromResult<string?>(openID))
                .Verifiable();

            // Act
            var actual = await subject.HandleAsync(AuthenticationScheme.OAuthLoginScheme, validAppID.ToString(), validCredential, "192.168.123.123");

            // Assert
            actual.User.Should().NotBeNull();
            actual.Challenge.HasValue.Should().BeFalse();
            actualLoginsCreated.Single().PartitionKey.Should().Be($"{(int)channel}|{validAppID.ToKey()}");
            actualLoginsCreated.Single().RowKey.Should().StartWith(openID);
            loginRepositoryMock.Verify();
            userRepositoryMock.Verify();
            actualLoginsCreated.Single().User.Should().Be(actualUsersCreated.Single().ID);
            mock.Verify();
        }


        [DataRow(AuthenticationKind.Wechat)]
        [DataRow(AuthenticationKind.Alipay)]
        [DataRow(AuthenticationKind.Apple)]
        [DataRow(AuthenticationKind.Google)]
        [DataRow(AuthenticationKind.Microsoft)]
        [DataTestMethod]
        public async Task HandleAsync_LoginNotFound_ThrowsAuthenticationRequiredException(AuthenticationKind channel)
        {
            // Arrange
            var validAppID = Guid.NewGuid();
            var validCredential = $"{channel}@123456";
            mock.Protected().Setup<Task<string?>>("GetOpenIDAsync", ItExpr.IsAny<Guid>(), ItExpr.IsAny<string>())
                .Returns(Task.FromResult<string?>(null))
                .Verifiable();

            // Act
            var act = async () => await subject.HandleAsync(AuthenticationScheme.OAuthLoginScheme, validAppID.ToString(), validCredential, "192.168.123.123");

            // Assert
            await act.Should().ThrowAsync<ApplicationException>().Where(e => e.ErrorCode == InternalError.InternalServerError);
        }
    }
}
