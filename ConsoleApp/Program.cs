// See https://aka.ms/new-console-template for more information
using Cryptography;

CryptographyService cryptographyService = new CryptographyService();

var keyPair = cryptographyService.GenerateKeyPair();
var message = "test";
var signature = cryptographyService.Sign(message, keyPair.PrivateKey);
var isVerified = cryptographyService.VerifySignature(message, signature, keyPair.PublicKey);

Console.WriteLine(isVerified);