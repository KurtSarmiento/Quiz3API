using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;

namespace Quiz3API.Utils
{
    public class JwtService
    {
        private readonly string secretKey = "9f3a7c2e5b1d8a4f6c0e92b7d5a3f8c1";
        public class AuthResponse
        {
            public string UserName { get; set; }
            public string Role { get; set; }
            public DateTime Expiration { get; set; }
            public string Token { get; set; }
        }

        public AuthResponse GenerateToken(string username, string role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(secretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, role)
                }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            //return tokenHandler.WriteToken(token);

            return new AuthResponse
            {
                UserName = username,
                Role = role,
                Expiration = tokenDescriptor.Expires.Value,
                Token = tokenHandler.WriteToken(token)
            };
        }
    }
}
