using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace TestApiJWT.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(100), Required]
        public string FirstName { get; set; }
        [MaxLength(100), Required]
        public string LastName { get; set; }





        public List<RefreshToken>? RefreshTokens { get; set; }



    }

}
