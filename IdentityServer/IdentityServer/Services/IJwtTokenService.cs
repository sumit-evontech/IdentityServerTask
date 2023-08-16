using IdentityServer.ViewModels;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace IdentityServer.Services
{
    public interface IJwtTokenService
    {
        public JwtSecurityToken CreateToken(List<Claim> authClaims);
        public string GenerateRefreshToken();
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        public ObjectResult RefreshToken(TokenModel tokenModel);
    }
}
