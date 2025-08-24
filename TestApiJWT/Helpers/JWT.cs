namespace TestApiJWT.Helpers
{
    public class JWT
    {
        // Here we pput the words we use in appsetind to use it in any place in the program 

        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double DeurationInDays { get; set; }

    }
}
