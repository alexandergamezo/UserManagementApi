namespace Data.Interfaces
{
    public interface IUnitOfWork
    {
        IRefreshTokensRepository RefreshTokensRepository { get; }
        Task SaveAsync();
    }
}
