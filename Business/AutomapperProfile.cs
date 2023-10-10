using AutoMapper;
using Business.Models;
using Data.Entities;
using Microsoft.AspNetCore.Identity;

namespace Business
{
    public class AutomapperProfile : Profile
    {
        private readonly UserManager<AppUser> _userManager;

        public AutomapperProfile(UserManager<AppUser> userManager)
        {
            _userManager = userManager;

            CreateMap<AppUser, RegisterModel>()
                .AfterMap(async (src, dest) => await MapRolesAsyncFromAppUser(src, dest));

            CreateMap<RegisterModel, AppUser>()
                .ForMember(dest => dest.Id, opt => opt.Ignore());
        }

        private async Task MapRolesAsyncFromAppUser(AppUser src, RegisterModel dest)
        {
            var roles = await _userManager.GetRolesAsync(src);
            dest.Role = new List<string>(roles);
        }
    }
}
