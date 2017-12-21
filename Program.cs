using System;
using System.Text;
using System.Linq;
using System.Drawing;
using Gma;
using Gma.QrCodeNet;
using Gma.QrCodeNet.Encoding;
using System.IO;
using Gma.QrCodeNet.Encoding.Windows.Render;
using System.Drawing.Imaging;
using System.Security.Cryptography;
using System.Diagnostics;

namespace IOTAQRGenerator
{
    /// <summary>
    /// A small program that creates an IOTA seed that can be encrypted using AES-256 bit.
    /// Using Gmamaldze's QRCode.Net library.
    /// </summary>
    class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length > 2)
            {
                Console.Write(Usage);
                return;
            }
            if (args.Length == 1)
            {
                try
                {
                    int mode = Convert.ToInt32(args[0].Replace("-", string.Empty));
                    switch (mode)
                    {
                        case 1:
                            Bitmap qr = GenerateBitmapQR(GenerateSeed());
                            Bitmap template = (Bitmap)Bitmap.FromFile("Templates/Template1.png");
                            for (int x = qr.Width, x1 = 0; x < (qr.Width * 2); x++, x1++)
                            {
                                for (int y = (template.Height - qr.Height) / 2, y1 = 0; y < (template.Height - qr.Height) / 2 + qr.Height; y++, y1++)
                                {
                                    template.SetPixel(x, y, qr.GetPixel(x1, y1));
                                }
                            }
                            template.Save("IOTAPrivateKey.png");
                            break;
                        case 2:
                            Console.Write("Invalid mode. Your key is not encrypted.");
                            break;
                        case 3:
                            GenerateQR(GenerateSeed(), "IOTAPrivateKey.png");
                            break;
                        case 4:
                            Console.Write("Invalid mode. Your key is not encrypted.");
                            break;
                    }
                }
                catch(Exception e)
                {
                    Console.Write(Usage);
                    File.AppendAllText("ErrorLog.txt", e.ToString() + "\r\n");
                    return;
                }
            }
            else
            {
                string key = args[0];
                try
                {
                    int mode = Convert.ToInt32(args[1].Replace("-", string.Empty));
                    switch (mode)
                    {
                        case 1:
                            Bitmap qr = GenerateBitmapQR(EncryptText(GenerateSeed(), key));
                            Bitmap template = (Bitmap)Bitmap.FromFile("Templates/Template2.png");
                            for (int x = qr.Width, x1 = 0; x < (qr.Width * 2); x++, x1++)
                            {
                                for (int y = (template.Height - qr.Height) / 2, y1 = 0; y < (template.Height - qr.Height) / 2 + qr.Height; y++, y1++)
                                {
                                    template.SetPixel(x, y, qr.GetPixel(x1, y1));
                                }
                            }
                            template.Save("IOTAPrivateKey.png");
                            break;
                        case 2:
                            Bitmap qr2 = GenerateBitmapQR(EncryptText(GenerateSeed(), key));
                            Bitmap template2 = (Bitmap)Bitmap.FromFile("Templates/Template3.png");
                            for (int x = qr2.Width, x1 = 0; x < (qr2.Width * 2); x++, x1++)
                            {
                                for (int y = (template2.Height - qr2.Height) / 2, y1 = 0; y < (template2.Height - qr2.Height) / 2 + qr2.Height; y++, y1++)
                                {
                                    template2.SetPixel(x, y, qr2.GetPixel(x1, y1));
                                }
                            }
                            template2.Save("IOTAPrivateKey.png");
                            break;
                        case 3:
                            GenerateQR(EncryptText(GenerateSeed(), key), "IOTAPrivateKey.png");
                            break;
                        case 4:
                            Bitmap qr4 = GenerateBitmapQR(EncryptText(GenerateSeed(), key));
                            Bitmap template4 = (Bitmap)Bitmap.FromFile("Templates/Template4.png");
                            for (int x = qr4.Width, x1 = 0; x < (qr4.Width * 2); x++, x1++)
                            {
                                for (int y = (template4.Height - qr4.Height) / 2, y1 = 0; y < (template4.Height - qr4.Height) / 2 + qr4.Height; y++, y1++)
                                {
                                    template4.SetPixel(x, y, qr4.GetPixel(x1, y1));
                                }
                            }
                            template4.Save("IOTAPrivateKey.png");
                            break;
                    }
                }
                catch(Exception e)
                {
                    Console.Write(Usage);
                    File.AppendAllText("ErrorLog.txt", e.ToString() + "\r\n");
                    return;
                }
            }
            Process.Start("IOTAPrivateKey.png");
        }

        private static string Usage = string.Format("Usage:\r\n\t\"IOTAQR.exe [password] [style]\"\r\n\tWhere:\r\n\tpassword\tEncrypt the code using AES 256 bit encryption (optional)\r\n\tstyle\t-1 Modern\r\n\t\t-2 Modern with encryption details\r\n\t\t-3 Only QR code\r\n\t\t-4 Only QR code with encryption details");

        /// <summary>
        /// Generates the seed
        /// </summary>
        /// <returns></returns>
        private static string GenerateSeed()
        {
            string seed = string.Empty;
            RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();
            string seedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            while (!seed.Contains("9"))
            {
                seed = string.Empty;
                byte[] indexes = new byte[81];
                cryptoServiceProvider.GetNonZeroBytes(indexes);
                for (int i = 0; i < 81; i++)
                {
                    seed += seedCharacters[indexes[i] % seedCharacters.Length];
                }
            }
            return seed;
        }

        /// <summary>
        /// Generates the QR code
        /// </summary>
        /// <param name="data"></param>
        /// <param name="filename"></param>
        private static void GenerateQR(string data, string filename)
        {
            QrEncoder qrEncoder = new QrEncoder(ErrorCorrectionLevel.H);
            QrCode qrCode = qrEncoder.Encode(data);

            GraphicsRenderer renderer = new GraphicsRenderer(new FixedModuleSize(5, QuietZoneModules.Two), Brushes.Black, Brushes.White);
            using (FileStream stream = new FileStream(filename, FileMode.Create))
            {
                renderer.WriteToStream(qrCode.Matrix, ImageFormat.Png, stream);
            }
        }

        /// <summary>
        /// Generates a Bitmap QR code. Used for generating modern images.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="filename"></param>
        private static Bitmap GenerateBitmapQR(string data)
        {
            QrEncoder qrEncoder = new QrEncoder(ErrorCorrectionLevel.H);
            QrCode qrCode = qrEncoder.Encode(data);

            GraphicsRenderer renderer = new GraphicsRenderer(new FixedModuleSize(5, QuietZoneModules.Two), Brushes.Black, Brushes.White);
            
            using (FileStream stream = new FileStream("temp.png", FileMode.Create))
            {
                renderer.WriteToStream(qrCode.Matrix, ImageFormat.Png, stream);
                return (Bitmap)Bitmap.FromStream(stream);
            }
        }
        #region Crypto

        /// <summary>
        /// SHA512 for generating the AES IV
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string SHA512(string input)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            using (var hash = System.Security.Cryptography.SHA512.Create())
            {
                var hashedInputBytes = hash.ComputeHash(bytes);

                // Convert to text
                // StringBuilder Capacity is 128, because 512 bits / 8 bits in byte * 2 symbols for byte 
                var hashedInputStringBuilder = new System.Text.StringBuilder(128);
                foreach (var b in hashedInputBytes)
                    hashedInputStringBuilder.Append(b.ToString("X2"));
                return hashedInputStringBuilder.ToString();
            }
        }

        private static string DecryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AESDecrypt(bytesToBeDecrypted, passwordBytes);

            string result = Encoding.UTF8.GetString(bytesDecrypted);

            return result;
        }

        private static string EncryptText(string input, string password)
        {
            // Get the bytes of the string
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AESEncrypt(bytesToBeEncrypted, passwordBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            return result;
        }

        private static byte[] AESDecrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = SHA256.Create().ComputeHash(passwordBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 2000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        private static byte[] AESEncrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = SHA256.Create().ComputeHash(passwordBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 2000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }
#endregion
    }
}
