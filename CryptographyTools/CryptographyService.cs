using CryptographyTools;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public class CryptographyService : ICryptographyService
    {
        RSACryptoServiceProvider RSACryptoServiceProvider { get; set; }

        public CryptographyService()
        {
            RSACryptoServiceProvider = new RSACryptoServiceProvider();
        }

        public KeyPair GenerateKeyPair()
        {
            var publicKey = ConvertKeyToBase64String(RSACryptoServiceProvider.ExportParameters(false), false);
            var privateKey = ConvertKeyToBase64String(RSACryptoServiceProvider.ExportParameters(true), true);

            return new KeyPair(publicKey, privateKey);
        }

        public string Sign(string message, string privateKey)
        {
            RSACryptoServiceProvider.ImportParameters(ConvertBase64StringToKey(privateKey, true));
            return Convert.ToBase64String(RSACryptoServiceProvider.SignData(Encoding.ASCII.GetBytes(message), RSA.Create()));
        }

        public bool VerifySignature(string message, string signature, string publicKey)
        {
            try
            {
                RSACryptoServiceProvider.ImportParameters(ConvertBase64StringToKey(publicKey, true));
                return RSACryptoServiceProvider.VerifyData(Encoding.ASCII.GetBytes(message), SHA256.Create(), Convert.FromBase64String(signature));
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private string ConvertKeyToBase64String(RSAParameters rsaParameters, bool isPrivateKey)
        {
            List<byte> byteArray = new List<byte>();

            if (isPrivateKey)
            {
                byteArray.AddRange(rsaParameters.D);
                byteArray.AddRange(rsaParameters.DP);
                byteArray.AddRange(rsaParameters.DQ);
                byteArray.AddRange(rsaParameters.InverseQ);
                byteArray.AddRange(rsaParameters.P);
                byteArray.AddRange(rsaParameters.Q);
            }

            byteArray.AddRange(rsaParameters.Exponent);
            byteArray.AddRange(rsaParameters.Modulus);

            return Convert.ToBase64String(byteArray.ToArray());
        }

        private RSAParameters ConvertBase64StringToKey(string key, bool isPrivateKey)
        {
            var byteArray = Convert.FromBase64String(key).ToList();

            RSAParameters rsaParameters = new RSAParameters();

            if (isPrivateKey)
            {
                rsaParameters.D = byteArray.Take(128).ToArray();
                rsaParameters.DP = byteArray.Take(64).ToArray();
                rsaParameters.DQ = byteArray.Take(64).ToArray();
                rsaParameters.InverseQ = byteArray.Take(64).ToArray();
                rsaParameters.P = byteArray.Take(64).ToArray();
                rsaParameters.Q = byteArray.Take(64).ToArray();
            }

            rsaParameters.Exponent = byteArray.Take(3).ToArray();
            rsaParameters.Modulus = byteArray.Take(128).ToArray();

            return rsaParameters;
        }
    }
}
