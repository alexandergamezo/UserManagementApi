using Data.Interfaces;
using Data.Repositories;

namespace Data.Data
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly UserManagementDbContext _context;

        public UnitOfWork(UserManagementDbContext context)
        {
            _context = context;
        }

        public IRefreshTokensRepository RefreshTokensRepository => new RefreshTokensRepository(_context);

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
