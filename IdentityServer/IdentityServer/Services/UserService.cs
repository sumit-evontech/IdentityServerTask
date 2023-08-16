using IdentityServer.CustomError;
using IdentityServer.Models;
using IdentityServer.Repository;
using IdentityServer.ViewModels;
using Microsoft.AspNetCore.Mvc;
using PasswordHashing;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace IdentityServer.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepo _userRepo;
        private readonly IRoleRepo _roleRepo;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IConfiguration _configuration;

        public UserService(IUserRepo userRepo, IRoleRepo roleRepo, IJwtTokenService jwtTokenService, IConfiguration configuration)
        {
            _userRepo = userRepo;
            _roleRepo = roleRepo;
            _jwtTokenService = jwtTokenService;
            _configuration = configuration;
        }
        public string RegisterUser(RegisterModel model)
        {
            UserModel ExistingUser = _userRepo.GetUserByUserName(model.Username);

            if(ExistingUser is not null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.Conflict, $"User '{model.Username} already exists'");
            }

            UserModel user = new()
            {
                Email = model.Email,
                UserName = model.Username,
                Password = PasswordHasher.Hash(model.Password),
                Role = model.Role.ToUpper(),
            };

            if (!_roleRepo.IsRoleExists(user.Role))
            {
                _roleRepo.AddRole(user.Role.ToUpper());
            }

            string response = _userRepo.AddUser(user);
            return response;

        }

        public ObjectResult LoginUser(LoginModel model)
        {
            UserModel user = _userRepo.GetUserByUserName(model.Username);

            if (user is null || !PasswordHasher.Validate(model.Password, user.Password))
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.Unauthorized, "Unauthorized");
            }

            List<Claim> authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            JwtSecurityToken token = _jwtTokenService.CreateToken(authClaims);
            string refreshToken = _jwtTokenService.GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            _userRepo.SaveUserChanges();

            return new ObjectResult(new
            {
                Status = "Success",
                Message = "Login Successfull",
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Expiration = token.ValidTo
            });
        }

        public ObjectResult RefreshAccessToken(TokenModel tokenModel)
        {
            if (string.IsNullOrEmpty(tokenModel.RefreshToken) || string.IsNullOrEmpty(tokenModel.AccessToken))
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.BadRequest, "Invalid client request");
            }

            string accessToken = tokenModel.AccessToken;
            string refreshToken = tokenModel.RefreshToken;

            ClaimsPrincipal principal = _jwtTokenService.GetPrincipalFromExpiredToken(accessToken);
            if (principal is null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.BadRequest, "Invalid access token or refresh token");
            }

            string username = principal.Identity.Name;

            UserModel user = _userRepo.GetUserByUserName(username);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.BadRequest, "Invalid access token or refresh token");
            }

            JwtSecurityToken newAccessToken = _jwtTokenService.CreateToken(principal.Claims.ToList());
            string newRefreshToken = _jwtTokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            _userRepo.SaveUserChanges();

            return new ObjectResult(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }

        public string RevokeUser(string userName)
        {
            UserModel user = _userRepo.GetUserByUserName(userName);
            if(user is null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.NotFound, "User not found");
            }

            user.RefreshToken = string.Empty;
            _userRepo.SaveUserChanges();
            return "User Revoked successfully";
        }
        public string RevokeAllUsers()
        {
            List<UserModel> users = _userRepo.GetUsers();

            foreach (UserModel user in users)
            {
                user.RefreshToken = string.Empty;
            }

            _userRepo.SaveUserChanges();
            return "All Users Revoked successfully";
        }
    }
}
