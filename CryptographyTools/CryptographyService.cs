using CryptographyTools;
using System;
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

        public static RSAParameters RsaPrivateParameter { get; set; }

        public KeyPair GenerateKeyPair()
        {
            var rsaPublicParameter = RSACryptoServiceProvider.ExportParameters(false);
            var publicKey = ConvertKeyToBase64String(rsaPublicParameter, false);

            var rsaPrivateParameter = RSACryptoServiceProvider.ExportParameters(true);
            var privateKey = ConvertKeyToBase64String(rsaPrivateParameter, true);

            RsaPrivateParameter = rsaPublicParameter;
            return new KeyPair(publicKey, privateKey);
        }

        public string Sign(string message, string privateKey)
        {
            try
            {
                var rsaParameters = ConvertBase64StringToKey(privateKey, true);
                RSACryptoServiceProvider.ImportParameters(rsaParameters);
                return Convert.ToBase64String(RSACryptoServiceProvider.SignData(Encoding.ASCII.GetBytes(message), SHA256.Create()));
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public bool VerifySignature(string message, string signature, string publicKey)
        {
            try
            {
                var rsaParameters = ConvertBase64StringToKey(publicKey, false);
                RSACryptoServiceProvider.ImportParameters(rsaParameters);
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

        public string ConvertKeyToBase64String(RSAParameters rsaParameters, bool isPrivateKey)
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

        public RSAParameters ConvertBase64StringToKey(string key, bool isPrivateKey)
        {
            var byteArray = Convert.FromBase64String(key).ToList();

            RSAParameters rsaParameters = new RSAParameters();
            int index = 0;
            if (isPrivateKey)
            {
                rsaParameters.D = byteArray.Take(128).ToArray();
                index += 128;
                rsaParameters.DP = byteArray.Skip(index).Take(64).ToArray();
                index += 64;
                rsaParameters.DQ = byteArray.Skip(index).Take(64).ToArray();
                index += 64;
                rsaParameters.InverseQ = byteArray.Skip(index).Take(64).ToArray();
                index += 64;
                rsaParameters.P = byteArray.Skip(index).Take(64).ToArray();
                index += 64;
                rsaParameters.Q = byteArray.Skip(index).Take(64).ToArray();
                index += 64;
            }

            rsaParameters.Exponent = byteArray.Skip(index).Take(3).ToArray();
            index += 3;
            rsaParameters.Modulus = byteArray.Skip(index).Take(128).ToArray();

            return rsaParameters;
        }

        public RSAParameters GetRSAPrivateKey(KeyPair keyPair)
        {
            return ConvertBase64StringToKey(keyPair.PrivateKey, true);
        }

        public RSAParameters GetRSAPublicKey(KeyPair keyPair)
        {
            return ConvertBase64StringToKey(keyPair.PublicKey, false);
        }
    }
}
