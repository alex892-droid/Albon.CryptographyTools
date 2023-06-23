﻿using CryptographyTools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography
{
    public interface ICryptographyService
    {
        public KeyPair GenerateKeyPair();

        public string Sign(string message, string privateKey);

        public bool VerifySignature(string message, string signature, string publicKey);
    }
}