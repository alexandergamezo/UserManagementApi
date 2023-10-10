using Data.Data;
using Data.Entities;
using Data.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Data.Repositories
{
    public class RefreshTokensRepository : IRefreshTokensRepository
    {
        private readonly UserManagementDbContext _db;

        public RefreshTokensRepository(UserManagementDbContext context)
        {
            _db = context;            
        }

        public async Task AddAsync(RefreshToken entity)
        {
            await _db.RefreshTokens.AddAsync(entity);
        }

        public async Task DeleteAsync(RefreshToken refreshToken)
        {
            if (await _db.RefreshTokens.FindAsync(refreshToken) == null) throw new ArgumentException("Invalid entity");
            await Task.Run(() => _db.RefreshTokens.Remove(refreshToken));
        }

        public async Task DeleteByIdAsync(string id)
        {
            var token = await _db.RefreshTokens.FindAsync(id);
            _db.RefreshTokens.Remove(token ?? throw new ArgumentException("Invalid refreshToken ID"));
        }

        public async Task<IEnumerable<RefreshToken>> GetAllAsync()
        {
            return await _db.RefreshTokens.ToListAsync();
        }

        public async Task<RefreshToken> GetByIdAsync(string id)
        {
            var refreshToken = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.JwtId == id.ToString());
            return refreshToken ?? new RefreshToken();
        }

        public async Task UpdateAsync(RefreshToken entity)
        {
            var existingToken = _db.RefreshTokens.Find(entity);
            if (existingToken != null)
            {
                await Task.Run(() => _db.Entry(existingToken).CurrentValues.SetValues(entity));
            }
        }
    }
}
