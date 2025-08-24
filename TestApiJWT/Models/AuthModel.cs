using System.Text.Json.Serialization;

namespace TestApiJWT.Models
{
    public class AuthModel
    {
        public string Message { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public bool IsAuthenticated { get; set; }

        public List<string> Roles { get; set; }


        public string Token { get; set; }
        //public DateTime ExpiresIn { get; set; }



        // We use JsonIgnore to ignore the column and not return it from database 
        [JsonIgnore]
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiration { get; set; }
    }

}
