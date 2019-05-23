using System;

namespace PALO.AuthorizationFilter
{
    public class AuthorizationFilterException : Exception
    {
        public AuthorizationFilterException(string message) : base(message)
        {
        }
    }
}