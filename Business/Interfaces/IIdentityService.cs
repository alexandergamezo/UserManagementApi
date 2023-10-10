using Business.Models;

namespace Business.Interfaces
{
    public interface IIdentityService
    {
        Task<RegisterResultModel?> RegisterUserAsync(RegisterModel registerModel);
        Task<AuthResultModel?> LoginUserAsync(LoginModel loginModel);
        Task<AuthResultModel?> VerifyAndGenerateTokenAsync(TokenRequestModel tokenRequestModel);
        Task<IEnumerable<RegisterModel>> GetFilteredUsersAsync(FilterUsersModel filters);
        Task<RegisterModel?> GetUserDetailsByIdAsync(string userId);
        Task UpdateUserAsync(RegisterModel registerModel, string id);
        Task DeleteAsync(string id);
        Task AddRoleToUser(string role, string id);        
    }
}
