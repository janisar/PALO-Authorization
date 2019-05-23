using PALO.AuthorizationFilter.Utils;
using Xunit;

namespace PALO.AuthorizationFilter.Tests.Utils
{
    public class TokenUtilTest
    {
        [Fact]
        public void ShouldGetRoleFromTokenWhenValidToken()
        {
            const string token =
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJicm9rZXJAcGFsby1pdC5jb20iLCJqdGkiOiJiOWQ4YTdjOS00ODI2LTRjMmUtOGMxYS1jNDU4MWQ2ZTY2NTIiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IjdjZDljNzBlLTM1ODQtNDE1MS04OTk2LTAzM2JmYThjMGJlMCIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IkJyb2tlciIsImV4cCI6MTU0NDA3NTQ1NywiaXNzIjoiaHR0cHM6Ly9jeXJ1c3MtY29yZS5henVyZXdlYnNpdGVzLm5ldC9hcGkiLCJhdWQiOiJodHRwczovL2N5cnVzcy1jb3JlLmF6dXJld2Vic2l0ZXMubmV0L2FwaSJ9.0oLu0tQMLIofpvDZtBkIy89tw5Lm5mubEnWxGYyOfNE";
            var role = TokenUtil.GetRoleFromToken(token);
            
            Assert.Equal("Broker", role);
        }
        
        [Fact]
        public void ShouldNotGetRoleFromTokenWhenInvalidToken()
        {
            const string token = "xxx";
            var role = TokenUtil.GetRoleFromToken(token);
            
            Assert.Null(role);
        }
        
        [Fact]
        public void ShouldGetIdFromTokenWhenValidToken()
        {
            const string token =
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJicm9rZXJAcGFsby1pdC5jb20iLCJqdGkiOiJiOWQ4YTdjOS00ODI2LTRjMmUtOGMxYS1jNDU4MWQ2ZTY2NTIiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IjdjZDljNzBlLTM1ODQtNDE1MS04OTk2LTAzM2JmYThjMGJlMCIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IkJyb2tlciIsImV4cCI6MTU0NDA3NTQ1NywiaXNzIjoiaHR0cHM6Ly9jeXJ1c3MtY29yZS5henVyZXdlYnNpdGVzLm5ldC9hcGkiLCJhdWQiOiJodHRwczovL2N5cnVzcy1jb3JlLmF6dXJld2Vic2l0ZXMubmV0L2FwaSJ9.0oLu0tQMLIofpvDZtBkIy89tw5Lm5mubEnWxGYyOfNE";
            var role = TokenUtil.GetIdFromToken(token);
            
            Assert.Equal("7cd9c70e-3584-4151-8996-033bfa8c0be0", role);
        }
        
        [Fact]
        public void ShouldNotGetIdFromTokenWhenInvalidToken()
        {
            const string token = "xxx";
            var role = TokenUtil.GetIdFromToken(token);
            
            Assert.Null(role);
        }

        [Fact]
        public void ShouldDecodeTokenWithPublicKey()
        {
            const string token =
                "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJicm9rZXJAcGFsby1pdC5jb20iLCJqdGkiOiI0MzYwZjZjYi0xNmNkLTQ5NDItYjYyMi0xOThlY2QwNDYzNzUiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IjdjZDljNzBlLTM1ODQtNDE1MS04OTk2LTAzM2JmYThjMGJlMCIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IkJyb2tlciIsImV4cCI6IjE1Njg5NTM5NzIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjUwMDAvYXBpIn0.MSsMGWuanJIJ5QLCZCwztaDU2A8F5DM5oJFBLf-mjakyjCqUEYejOsyRrCj-wH8wIUXXHFcDRChIBp-pQONqsQ";

            Assert.True(TokenUtil.ValidateToken(token));
        }
    }
}