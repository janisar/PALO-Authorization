using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PALO.AuthorizationFilter.Utils;

namespace PALO.AuthorizationFilter
{
    public class AuthorizationFilter : IAuthorizationFilter
    {
        private readonly Claim _claim;

        public AuthorizationFilter(Claim claim)
        {
            _claim = claim;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (string.IsNullOrWhiteSpace(Configuration.PublicKey))
            {
                throw new AuthorizationFilterException("Public key not provided to validate the token to.");
            }
            
            var token = context.HttpContext.Request.Headers["Authorization"];
            var claims = _claim.Value.Split(",");

            if (!string.IsNullOrWhiteSpace(token) && TokenUtil.ValidateToken(token))
            {
                var role = TokenUtil.GetRoleFromToken(token);
                if (claims.Length == 0 || Array.IndexOf(claims, role) == -1)
                {
                    context.Result = new ForbidResult();
                }
            }
            else
                context.Result = new ForbidResult();
        }
    }
}