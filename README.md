# CryptographyTools

    public interface ICryptographyService
    {
        public KeyPair GenerateKeyPair();

        public string Sign(string message, string privateKey);

        public bool VerifySignature(string message, string signature, string publicKey);
    }
