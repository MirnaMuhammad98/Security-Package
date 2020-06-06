using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> squarePlainTextCols = new List<int>();
            List<int> plainTextInverse = new List<int>();
            List<int> partCipherTextRows = new List<int>();
            List<int> testCipherTextCols = new List<int>();
            List<int> testPlainText = new List<int>();
            List<int> key = new List<int>();
            int ColsplainText = plainText.Count() / 2;
            for (int i=0; i< ColsplainText; i++)
            {
                for (int j =0; j<ColsplainText; j++)
                {
                    if (i == j)
                        continue;
                    //clear all lists
                    squarePlainTextCols.Clear();
                    plainTextInverse.Clear();
                    partCipherTextRows.Clear();
                    key.Clear();
                    testCipherTextCols.Clear();
                    testPlainText.Clear();
                    //get square plain text matrix col by col
                    squarePlainTextCols.Add(plainText[i * 2]);
                    squarePlainTextCols.Add(plainText[i * 2  + 1]);
                    squarePlainTextCols.Add(plainText[j * 2]);
                    squarePlainTextCols.Add(plainText[j * 2 + 1]);
                    int det = GetDet(squarePlainTextCols);
                    int detInverse = GetDetInverse(det);
                    if (detInverse == 0)
                        continue;
                    plainTextInverse = GetPlainTextInverse(squarePlainTextCols, detInverse);
                    partCipherTextRows.Add(cipherText[i * 2]);
                    partCipherTextRows.Add(cipherText[j * 2]);
                    partCipherTextRows.Add(cipherText[i * 2 + 1]);
                    partCipherTextRows.Add(cipherText[j * 2 + 1]);
                    key = CalcKey(plainTextInverse, partCipherTextRows);
                    key = GetTranspose(key);
                    testCipherTextCols = Encrypt(squarePlainTextCols,key );
                    List<int> partCipherTextCols = GetTranspose(partCipherTextRows);
                    if (testCipherTextCols.SequenceEqual(partCipherTextCols))
                        return key;

                }
            }
            throw new InvalidAnlysisException();
        }
        public List<int>CalcKey (List<int> plainText , List<int> cipherText)
        {
            List<int> key = Encrypt(plainText, cipherText);
            return key;
        }
        public List<int> GetPlainTextInverse(List<int>plainText, int detInverse)
        {
            List<int> plainTextInverse = new List<int>();
            for (int i = 0; i < plainText.Count(); i++)
            {
                int currValue;
                // not first not last element in key matrix
                if (i != 0 && i != plainText.Count() - 1)
                    currValue = -1 * detInverse * plainText[i];
                // first or last element in key matrix
                else
                    currValue = detInverse * plainText[i];
                int modCurrValue = GetMod(currValue);
                plainTextInverse.Add(modCurrValue);
            }
            //swap first and last element in the key matrix
            int temp = plainTextInverse[0];
            plainTextInverse[0] = plainTextInverse[3];
            plainTextInverse[3] = temp;
            return plainTextInverse;
        }
        public List<int> GetPlainTextInverse3x3 (List<int> plainText, int detInverse)
        {
            List<int> plainTextInverse = new List<int>();
            List<int> plainTranspose = new List<int>();
            // Get Dimensions of key
            int m = 3;
            for (int i = 0; i < m; i++)
            {
                // for each col in key matrix
                for (int j = 0; j < m; j++)
                {
                    int iPlusj = i + j;
                    int subDet = GetSubDet(plainText, i, j);
                    int sum = detInverse * (int)Math.Pow(-1, Convert.ToDouble(iPlusj)) * subDet;
                    //get mod 26
                    int mod = GetMod(sum);
                    // add to the key inverse matrix
                    plainTextInverse.Add(mod);
                }
            }
            // get the transpose of the key inverse matrix
            plainTranspose = GetTranspose(plainTextInverse);
            return plainTranspose;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> keyInverse = new List<int>();
            List<int> keyTranspose = new List<int>();
            // Get Dimensions of key
            int m = (int)Math.Sqrt(key.Count);
            // Get the Determinant of the key matrix
            int det = GetDet(key);
            // Get the inverse of the determinant
            int detInverse = GetDetInverse(det);
            if (detInverse == 0)
                throw new InvalidAnlysisException();
            // key = 3x3
            if (m>2)
            {
                // for each row in key matrix
                for (int i = 0; i < m; i++)
                {
                    // for each col in key matrix
                    for (int j = 0; j < m; j++)
                    {
                        int iPlusj = i + j;
                        int subDet = GetSubDet(key, i, j);
                        int sum = detInverse * (int)Math.Pow(-1, Convert.ToDouble(iPlusj)) * subDet;
                        //get mod 26
                        int mod = GetMod(sum);
                        // add to the key inverse matrix
                        keyInverse.Add(mod);
                    }
                }
                // get the transpose of the key inverse matrix
                keyTranspose = GetTranspose(keyInverse);
            }
            // key = 2x2
            else
            {
                // for each element in key matrix
                for (int i = 0; i<key.Count(); i++)
                {
                    int currValue;
                    // not first not last element in key matrix
                    if (i !=0 && i != key.Count()-1)
                        currValue = -1 * detInverse * key[i];
                    // first or last element in key matrix
                    else
                        currValue = detInverse * key[i];
                    int modCurrValue = GetMod(currValue);
                    keyInverse.Add(modCurrValue);
                }
                //swap first and last element in the key matrix
                int temp = keyInverse[0];
                keyInverse[0] = keyInverse[3];
                keyInverse[3] = temp ;
                keyTranspose = keyInverse;
            }
            //get plain text
            List<int> plainText = Encrypt(cipherText, keyTranspose);
            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            //looping the plain text
            for (int i =0; i<plainText.Count(); i+= m)
            {
                for (int x=0; x<key.Count(); x+= m  )
                {
                    int sum = 0;
                    for (int y = 0; y < m; y++ )
                    {
                        sum += key[x + y] * plainText[i + y];
                    }
                    int div = sum / 26;
                    int modSum = sum -(div * 26);
                    cipherText.Add(modSum);
                }
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> squarePlainTextCols = new List<int>();
            List<int> plainTextInverse = new List<int>();
            List<int> partCipherTextRows = new List<int>();
            List<int> testCipherTextCols = new List<int>();
            List<int> testPlainText = new List<int>();
            List<int> key = new List<int>();
            int ColsplainText = plainText.Count() / 3;
            for (int i = 0; i < ColsplainText; i++)
            {
                for (int j = 0; j < ColsplainText; j++)
                {
                    for (int k =0; k< ColsplainText; k++)
                    {
                        if (i == j || i == k || j == k)
                            continue;
                        //clear all lists
                        squarePlainTextCols.Clear();
                        plainTextInverse.Clear();
                        partCipherTextRows.Clear();
                        key.Clear();
                        testCipherTextCols.Clear();
                        testPlainText.Clear();
                        //get square plain text matrix col by col
                        squarePlainTextCols.Add(plainText[i * 3]);
                        squarePlainTextCols.Add(plainText[i * 3 + 1]);
                        squarePlainTextCols.Add(plainText[i * 3 + 2]);
                        squarePlainTextCols.Add(plainText[j * 3]);
                        squarePlainTextCols.Add(plainText[j * 3 + 1]);
                        squarePlainTextCols.Add(plainText[j * 3 + 2]);
                        squarePlainTextCols.Add(plainText[k * 3]);
                        squarePlainTextCols.Add(plainText[k * 3 + 1]);
                        squarePlainTextCols.Add(plainText[k * 3 + 2]);
                        int det = GetDet(squarePlainTextCols);
                        int detInverse = GetDetInverse(det);
                        if (detInverse == 0)
                            continue;
                        plainTextInverse = GetPlainTextInverse3x3(squarePlainTextCols, detInverse);
                        partCipherTextRows.Add(cipherText[i * 3]);
                        partCipherTextRows.Add(cipherText[j * 3]);
                        partCipherTextRows.Add(cipherText[k * 3]);
                        partCipherTextRows.Add(cipherText[i * 3 + 1]);
                        partCipherTextRows.Add(cipherText[j * 3 + 1]);
                        partCipherTextRows.Add(cipherText[k * 3 + 1]);
                        partCipherTextRows.Add(cipherText[i * 3 + 2]);
                        partCipherTextRows.Add(cipherText[j * 3 + 2]);
                        partCipherTextRows.Add(cipherText[k * 3 + 2]);
                        key = CalcKey(plainTextInverse, partCipherTextRows);
                        key = GetTranspose(key);
                        testCipherTextCols = Encrypt(squarePlainTextCols, key);
                        List<int> partCipherTextCols = GetTranspose(partCipherTextRows);
                        if (testCipherTextCols.SequenceEqual(partCipherTextCols))
                            return key;
                    }
                }
            }
            throw new InvalidAnlysisException();
        }
        public int GetDet (List<int> key)
        {

            int modDet=0;
            int m = (int)Math.Sqrt(key.Count());
            // key = 3x3
            if (m>2)
            {
                int det;
                int firstTerm = key[0] * ((key[4] * key[8]) - (key[5] * key[7]));
                int secTerm = -key[1] * ((key[3] * key[8]) - (key[5] * key[6]));
                int thirdTerm = key[2] * ((key[3] * key[7]) - (key[4] * key[6]));
                det = firstTerm + secTerm + thirdTerm;
                modDet = GetMod(det);
            }
            // key = 2x2
            else
            {
                modDet = GetSubDet(key, 3, 3);
            }
            return modDet ;
        }
        public int GetSubDet (List<int> key , int row , int col)
        {
            List<int> keyElements = new List<int>();
            int m = (int)Math.Sqrt(key.Count());
            // key = 3x3
            if (m>2)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        if (i == row || j == col)
                            continue;
                        else
                            keyElements.Add(key[i * m + j]);
                    }
                }
                int firstTerm = keyElements[0] * keyElements[3];
                int secTerm = keyElements[1] * keyElements[2];
                int subDet = firstTerm - secTerm;
                return GetMod(subDet);
            }
            else
            {
                int firstTerm = key[0] * key[3];
                int secTerm = key[1] * key[2];
                int subDet = firstTerm - secTerm;
                return GetMod(subDet);
            }

            return 0;
        }
        public List<int> GetTranspose ( List<int> key)
        {
            List<int> keyTrasnpose = new List<int>();
            int m = (int)Math.Sqrt(key.Count());
            for (int i = 0; i<m; i++)
            {
                for(int j=0; j<key.Count(); j+= m )
                {
                    keyTrasnpose.Add(key[i + j]);
                }
            }
            return keyTrasnpose;
        }
        // get detInverse by Extended Euclidean
        public int GetDetInverse (int det)
        {
            int T1, T2, T3;
            int A1 = 1, A2 = 0, A3 = 26 , B1= 0 , B2 = 1 , B3 = det ;
            while(true)
            {
                if (B3 == 0)
                    return 0;
                else if (B3 == 1)
                {
                    return GetMod( B2);
                }
                int Q = A3 / B3;
                T1 = A1 - (Q * B1);
                T2 = A2 - (Q * B2);
                T3 = A3 - (Q * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = T1;
                B2 = T2;
                B3 = T3;
            }
            return 0;
        }
        public int GetMod(int num)
        {
            int div, mod=0;
            if (num > 0)
            {
                 div = num / 26;
                 mod = num - (div * 26);
            }
            else if (num < 0)
            {
                while (num < 0)
                    num += 26;
                mod = num;
            }
            return mod;
        }
    }
}
