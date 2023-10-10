using Data.Entities;

namespace Data.Interfaces
{
    public interface IRefreshTokensRepository : IRepository<RefreshToken>
    {
        Task DeleteAsync(RefreshToken refreshToken);
    }
}
