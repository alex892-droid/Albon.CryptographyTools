using CryptographyTools;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public static class CryptographyService
    {
        static RSACryptoServiceProvider RSACryptoServiceProvider { get; set; }

        static CryptographyService()
        {
            RSACryptoServiceProvider = new RSACryptoServiceProvider();
        }

        public static KeyPair GenerateKeyPair()
        {
            var rsaPublicParameter = RSACryptoServiceProvider.ExportParameters(false);
            var publicKey = ConvertKeyToBase64String(rsaPublicParameter, false);

            var rsaPrivateParameter = RSACryptoServiceProvider.ExportParameters(true);
            var privateKey = ConvertKeyToBase64String(rsaPrivateParameter, true);

            return new KeyPair(publicKey, privateKey);
        }

        public static string Sign(string message, string privateKey)
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

        public static bool VerifySignature(string message, string signature, string publicKey)
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

        public static string ConvertKeyToBase64String(RSAParameters rsaParameters, bool isPrivateKey)
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

        public static RSAParameters ConvertBase64StringToKey(string key, bool isPrivateKey)
        {
            List<byte> byteArray = new List<byte>();
            try
            {
                byteArray = Convert.FromBase64String(key).ToList();
            }
            catch(Exception e) 
            {
                throw new ArgumentException("Key need to be base 64 encoded.", e);
            }

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

        public static RSAParameters GetRSAPrivateKey(KeyPair keyPair)
        {
            return ConvertBase64StringToKey(keyPair.PrivateKey, true);
        }

        public static RSAParameters GetRSAPublicKey(KeyPair keyPair)
        {
            return ConvertBase64StringToKey(keyPair.PublicKey, false);
        }
    }
}
