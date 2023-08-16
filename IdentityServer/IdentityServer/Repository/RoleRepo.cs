using IdentityServer.Database;
using IdentityServer.Models;

namespace IdentityServer.Repository
{
    public class RoleRepo : IRoleRepo
    {
        private readonly ApplicationDbContext _context;

        public RoleRepo(ApplicationDbContext context)
        {
            _context = context;
        }
        public void AddRole(string roleName)
        {
            _context.Roles.Add(new RoleModel { RoleName = roleName });
            _context.SaveChanges();
        }

        public bool IsRoleExists(string roleName)
        {
            return _context.Roles.FirstOrDefault(r=> r.RoleName == roleName) == null? false : true;
        }
    }
}
