namespace Data.Interfaces
{
    public interface IRepository<TEntity> where TEntity : class
    {
        Task AddAsync(TEntity entity);
        Task<IEnumerable<TEntity>> GetAllAsync();
        Task<TEntity> GetByIdAsync(string id);        
        Task DeleteByIdAsync(string id);
        Task UpdateAsync(TEntity entity);
    }
}
