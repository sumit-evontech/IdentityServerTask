using Microsoft.AspNetCore.Identity;
using RefreshToken.Auth;

namespace RefreshToken.Services
{
    public interface IUserService
    {
        public Task<IdentityResult> RegisterUser(RegisterModel model);
        public Task<IdentityResult> RegisterAdmin(RegisterModel model);
        public Task<LoginReturn> LoginUser(LoginModel model);
        public Task<string> RevokeUser(string userName);
        public Task<string> RevokeAllUsers();
    }
}
