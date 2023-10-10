using System.ComponentModel.DataAnnotations.Schema;

namespace Data.Entities
{
    public class RefreshToken
    {
        public Guid RefreshTokenId { get; set; }
        public string? Token { get; set; }
        public string? JwtId { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime DateAdded { get; set; }
        public DateTime DateExpire { get; set; }


        public string? UserId { get; set; }
        [ForeignKey(nameof(UserId))]
        public AppUser? User { get; set; }


    }
}
