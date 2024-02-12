using Raven.Identity;

namespace Infrastructure
{
    public class CustomUser : IdentityUser
    {
        public const string AdminRole = "Admin";
        public const string ManagerRole = "Manager";

        public string? FirstName { get; set; }
        public string? LastName { get; set; }

    }
}
