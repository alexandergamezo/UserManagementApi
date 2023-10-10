namespace Business.Interfaces
{
    public interface ICrud<TModel> where TModel : class
    {
        Task<IEnumerable<TModel>> GetAllAsync();

        Task<TModel> GetByIdAsync(string id);

        Task AddAsync(TModel model);

        Task UpdateAsync(TModel model, string id);

        Task DeleteAsync(string modelId);
    }
}
