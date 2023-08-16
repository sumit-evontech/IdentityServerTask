using IdentityServer.Models;

namespace IdentityServer.Repository
{
    public interface IUserRepo
    {
        public string AddUser(UserModel model);
        public UserModel GetUserByUserName(string username);

        public List<UserModel> GetUsers();
        public void SaveUserChanges();
    }
}
