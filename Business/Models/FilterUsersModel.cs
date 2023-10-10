using System.ComponentModel;

namespace Business.Models
{
    public class FilterUsersModel
    {
        [DefaultValue(null)]
        public string? Id { get; set; }

        [DefaultValue(null)]
        public string? Name { get; set; }

        [DefaultValue(null)]
        public int? Age { get; set; }

        [DefaultValue(null)]
        public string? Email { get; set; }

        [DefaultValue(null)]
        public string? Role { get; set; }

        [DefaultValue(1)]
        public int Page { get; set; }

        [DefaultValue(10)]
        public int PageSize { get; set; }

        [DefaultValue(null)]
        public string? SortBy { get; set; }

        [DefaultValue(true)]
        public bool IsSortAscending { get; set; }
    }
}
