using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TestSSLCertificate
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            TestSSLStatus("www.google.com.tr");
            TestSSLStatus("www.d-teknoloji.com.tr");
            TestSSLStatus("www.aaaexpos.com");
        }

        private static void TestSSLStatus(string url)
        {
            Console.WriteLine($"-----------{url} Certificate Details------------");
            Console.WriteLine();
            HttpClientHandler handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = CustomCallback };

            using (HttpClient client = new HttpClient(handler))
            {
                try
                {
                    HttpResponseMessage response = client.GetAsync($"https://{url}/").GetAwaiter().GetResult();
                    Console.WriteLine($"Response Code: {(int)response.StatusCode}({response.StatusCode})");
                }
                catch (Exception)
                {
                    Console.WriteLine($"{url} isn't bind an SSL certificate");
                }
            }
            Console.WriteLine($"-----------End of {url} Certificate Details------------");
            Console.WriteLine();
            Console.WriteLine();
        }
        private static bool CustomCallback(HttpRequestMessage requestMessage, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
        {

            PrintCertificateDetails(cert);
            int counter = 1;
            Console.WriteLine("-----------Chain Certificate Details------------");
            Console.WriteLine();
            foreach (X509ChainElement element in chain.ChainElements)
            {
                Console.WriteLine($"Chain Certificate {counter++}");
                Console.WriteLine();
                PrintCertificateDetails(element.Certificate);
            }

            return errors == SslPolicyErrors.None;
        }

        private static void PrintCertificateDetails(X509Certificate2 cert)
        {
            Console.WriteLine("------------Certificate Info------------");
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"Issuer: {cert.Issuer}");

            DateTime certExpirationDate = DateTime.Parse(cert.GetExpirationDateString());
            string remaingDaysToExpire = (certExpirationDate - DateTime.Now).TotalDays.ToString("F0");

            Console.WriteLine($"Expire Date: {cert.GetExpirationDateString()} ({remaingDaysToExpire} days left)");
            //Console.WriteLine($"Certificate Public Key: {cert.GetPublicKeyString()}");
            Console.WriteLine($"Certificate Serial Number: {cert.GetSerialNumberString()}");
            Console.WriteLine("------------End Of Certificate Info------------");
            Console.WriteLine();
        }
    }
}
