using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace PALO.AuthorizationFilter.Attributes
{
    public class AuthRolesAttribute : TypeFilterAttribute
    {
        public AuthRolesAttribute(string claimValue) : base(typeof(AuthorizationFilter))
        {
            Arguments = new object[] { new Claim(ClaimTypes.Role, claimValue) };
        }
    }
}