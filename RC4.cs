using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        private List<byte> S, T;
        private List<byte> finalByteText;
        private string finalStringText = "";
        private bool hex;

        public override string Decrypt(string cipherText, string key)
        {
            return Execute(cipherText, key);
        }

        public override string Encrypt(string plainText, string key)
        {
            return Execute(plainText, key);
        }

        private string Execute(string target, string key)
        {
            var encodedKey = encodeStringToBytes(key);
            initialze(encodedKey);
            KSA();
            PRGA(target);
            string result;
            if (hex)
                result = "0x" + BitConverter.ToString(finalByteText.ToArray()).Replace("-", "");
            else
                result = finalStringText;
            return result;
        }

        private void initialze(List<byte> key)
        {
            S = new List<byte>();
            T = new List<byte>();
            finalByteText = new List<byte>();
            int noRepeating = 256 / key.Count,
                remainder = 256 % key.Count;
            for (int i = 0; i < noRepeating; i++)
                T.AddRange(key);
            T.AddRange(key.GetRange(0, remainder)); //We need to check the case when remainder = 0 

            for (int i = 0; i < 256; i++)
            {
                S.Add((byte)i);
            }
        }

        private void KSA()
        {
            for (int i = 0, j = 0; i < T.Count; i++)
            {
                j = (j + S[i] + T[i]) % T.Count;
                swap(S, i, j);
            }
        }

        private void PRGA(string targetText)
        {
            var encodedTarget = encodeStringToBytes(targetText);
            int i = 0, j = 0;
            foreach (var character in encodedTarget)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                swap(S, i, j);
                int t = (S[i] + S[j]) % 256;
                byte k = S[t];
                finalByteText.Add((byte)(encodedTarget[i - 1] ^ k));
                finalStringText += Convert.ToChar(Convert.ToInt32(targetText[i - 1]) ^ k);
            }
        }

        private void swap(List<byte> list, int i, int j)
        {
            byte temp = list[i];
            list[i] = list[j];
            list[j] = temp;
        }

        private List<byte> encodeStringToBytes(string targetText)
        {
            List<byte> result;
            if (targetText.Substring(0, 2) == "0x")
            {
                targetText = targetText.Substring(2);
                byte[] hexBytes = Enumerable.Range(0, targetText.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(targetText.Substring(x, 2), 16))
                    .ToArray();
                result = new List<byte>(hexBytes);
                hex = true;
            }
            else
                result = Encoding.ASCII.GetBytes(targetText).ToList();

            return result;
        }
    }
}
