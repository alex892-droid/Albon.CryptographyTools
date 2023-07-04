// See https://aka.ms/new-console-template for more information
using Cryptography;

var keyPair = CryptographyService.GenerateKeyPair();
var message = "test";
var signature = CryptographyService.Sign(message, keyPair.PrivateKey);
var isVerified = CryptographyService.VerifySignature(message, signature, keyPair.PublicKey);

Console.WriteLine(isVerified);