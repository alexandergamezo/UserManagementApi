using Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Data.Data
{
    public class UserManagementDbContext : IdentityDbContext<AppUser>
    {
        public UserManagementDbContext(DbContextOptions<UserManagementDbContext> options) : base(options)
        { }

        public DbSet<AppUser> AppUsers { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<IdentityUserLogin<string>>().HasKey(login => login.UserId);
            builder.Entity<IdentityUserRole<string>>().HasKey(r => new { r.UserId, r.RoleId });
            builder.Entity<IdentityUserToken<string>>().HasKey(token => new { token.UserId, token.LoginProvider, token.Name });
        }
    }
}
