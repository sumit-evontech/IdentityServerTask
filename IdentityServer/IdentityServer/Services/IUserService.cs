using IdentityServer.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Services
{
    public interface IUserService
    {
        public string RegisterUser(RegisterModel model);
        public ObjectResult RefreshAccessToken(TokenModel tokenModel);
        public ObjectResult LoginUser(LoginModel model);
        public string RevokeUser(string userName);
        public string RevokeAllUsers();
    }
}
