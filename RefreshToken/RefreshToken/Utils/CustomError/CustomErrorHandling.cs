using System.Net;

namespace UserServer.Utils
{
    public class CustomErrorHandling : Exception
    {
        public HttpStatusCode StatusCode { get; private set; }
        public CustomErrorHandling(HttpStatusCode statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}
