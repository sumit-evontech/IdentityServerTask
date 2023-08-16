namespace RefreshToken.Auth
{
    public class LoginReturn
    {
        public string Token {  get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
    }
}
