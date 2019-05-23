using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PALO.AuthorizationFilter.Utils
{
    public static class TokenUtil
    {
        public static string GetRoleFromToken(string bearerToken)
        {
            var jwtToken = GetJwtSecurityToken(bearerToken);
            return jwtToken?.Claims.First(claim => claim.Type.Equals(ClaimTypes.Role)).Value;
        }
        
        public static string GetIdFromToken(string bearerToken)
        {
            var jwtToken = GetJwtSecurityToken(bearerToken);
            return jwtToken?.Claims.First(claim => claim.Type.Equals(ClaimTypes.NameIdentifier)).Value;
        }

        private static JwtSecurityToken GetJwtSecurityToken(string bearerToken)
        {
            var token = bearerToken.Split("Bearer ");
            return token?.Length <= 1 ? null : GetJwtSecurityToken(token);
        }

        private static JwtSecurityToken GetJwtSecurityToken(IReadOnlyList<string> token)
        {
            try
            {
                return new JwtSecurityToken(token[1]);
            }
            catch (Exception)
            {
                throw new AuthorizationFilterException("Invalid token provided");
            }
        }

        public static bool ValidateToken(string bearerToken)
        {
            try
            {
                var token = bearerToken.Split("Bearer ");
                var jwtToken = GetJwtSecurityToken(bearerToken);
                if (!ValidateExpiry(jwtToken))
                    throw new AuthorizationFilterException("Token expired");
                return Decode(token[1], Configuration.PublicKey);
            }
            catch (AuthorizationFilterException)
            {
                return false;
            }
        }

        private static bool ValidateExpiry(SecurityToken jwtToken)
        {
            return jwtToken.ValidTo > DateTime.UtcNow;
        }

        private static bool Decode(string token, string key)
        {
            var parts = token.Split('.');
            var base64UrlDecode = Base64UrlDecode(parts[2]);

            var keyBytes = Convert.FromBase64String(key);

            var asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            var rsaKeyParameters = (RsaKeyParameters) asymmetricKeyParameter;
            var rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);


            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            var deFormatter = new RSAPKCS1SignatureDeformatter(rsa);
            deFormatter.SetHashAlgorithm("SHA256");
            if (!deFormatter.VerifySignature(hash, base64UrlDecode))
                throw new AuthorizationFilterException("Invalid signature");

            return true;
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4)
            {
                case 0: break;
                case 1:
                    output += "===";
                    break;
                case 2:
                    output += "==";
                    break;
                case 3:
                    output += "=";
                    break;
                default: throw new AuthenticationException("Illegal base64url string!");
            }

            var converted = Convert.FromBase64String(output);
            return converted;
        }
    }
}