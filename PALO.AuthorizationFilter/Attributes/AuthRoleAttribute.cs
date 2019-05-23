using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using PALO.AuthorizationFilter;

namespace AuthenticationFilter.Attributes
{
    public class AuthRoleAttribute : TypeFilterAttribute
    {
        public AuthRoleAttribute(string claimValue) : base(typeof(AuthorizationFilter))
        {
            Arguments = new object[] {new Claim(ClaimTypes.Role, claimValue)};
        }
    }
}