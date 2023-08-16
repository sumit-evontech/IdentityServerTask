using IdentityServer.Database;
using IdentityServer.Models;

namespace IdentityServer.Repository
{
    public class UserRepo : IUserRepo
    {
        private readonly ApplicationDbContext _context;

        public UserRepo(ApplicationDbContext context)
        {
            _context = context;
        }
        public string AddUser(UserModel model)
        {
            _context.Users.Add(model);
            _context.SaveChanges();
            return "User Registered Successfully";
        }

        public void SaveUserChanges()
        {
            _context.SaveChanges();
        }

        public UserModel GetUserByUserName(string username)
        {
            return _context.Users.FirstOrDefault(x => x.UserName == username);
        }

        public List<UserModel> GetUsers()
        {
            return _context.Users.ToList();
        }
    }
}
