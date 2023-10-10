using Microsoft.AspNetCore.Identity;

namespace Data.Entities
{
    public class AppUser : IdentityUser
    {
        public int Age { get; set; }
    }
}
