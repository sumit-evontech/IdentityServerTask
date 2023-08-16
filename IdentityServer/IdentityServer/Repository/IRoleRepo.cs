namespace IdentityServer.Repository
{
    public interface IRoleRepo
    {
        public void AddRole(string  roleName);
        public bool IsRoleExists(string roleName);
    }
}
