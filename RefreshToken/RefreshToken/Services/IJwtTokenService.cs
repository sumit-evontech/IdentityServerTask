using Microsoft.AspNetCore.Mvc;
using RefreshToken.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RefreshToken.Services
{
    public interface IJwtTokenService
    {
        public JwtSecurityToken CreateToken(List<Claim> authClaims);
        public string GenerateRefreshToken();
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        public Task<ObjectResult> RefreshToken(TokenModel tokenModel);
    }
}
