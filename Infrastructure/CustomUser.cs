using Raven.Identity;

namespace Infrastructure
{
    public class CustomUser : IdentityUser
    {
        public const string AdminRole = "Admin";
        public const string UserRole = "User";
        
        public string? FirstName { get; set; }
        public string? LastName { get; set; }

    }
}
