using Microsoft.AspNetCore.Identity;
using RefreshToken.Auth;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using UserServer.Utils;

namespace RefreshToken.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly IConfiguration _configuration;

        public UserService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IJwtTokenService jwtTokenService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtTokenService = jwtTokenService;
            _configuration = configuration;
        }

        public async Task<IdentityResult> RegisterUser(RegisterModel model)
        {
            ApplicationUser IsUserExists = await _userManager.FindByNameAsync(model.Username);

            if (IsUserExists != null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.Conflict, $"User '{model.Username}' already exists.");
            }

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.InternalServerError, "User creation failed! Please check user details and try again.");
            }
            return result;
        }
        public async Task<IdentityResult> RegisterAdmin(RegisterModel model)
        {
            ApplicationUser IsUserExists = await _userManager.FindByNameAsync(model.Username);

            if (IsUserExists != null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.Conflict, $"Admin '{model.Username}' already exists.");
            }

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.InternalServerError, "Admin creation failed! Please check user details and try again.");
            }

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            }
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
            {
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            }

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }

            return result;
        }
            
        public async Task<LoginReturn> LoginUser(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user == null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.Unauthorized, "Unauthorized");
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = _jwtTokenService.CreateToken(authClaims);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

            await _userManager.UpdateAsync(user);

            return new LoginReturn
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Expiration = token.ValidTo
            };
        }

        public async Task<string> RevokeUser(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);

            if(user == null)
            {
                throw new CustomErrorHandling(System.Net.HttpStatusCode.BadRequest, "Invalid Username");
            }
            user.RefreshToken = string.Empty;
            await _userManager.UpdateAsync(user);

            return "User revoked Successfully";
        }

        public async Task<string> RevokeAllUsers()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }

            return "Users Revoked successfully";
        }
    }
}
