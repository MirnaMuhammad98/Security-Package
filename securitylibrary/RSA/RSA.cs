using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            // Get n
            long n = p * q;
            NumberTheory calc = new NumberTheory();
            // Get C = M^e mod n
            int C = (int)calc.FastPower(M, e, n);
            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            long n = p * q;
            // Get phi(n)
            // Call Euclidean Extended to get d
            NumberTheory calc = new NumberTheory();
            long d = calc.GetMultiplicativeInverse(e, calc.Phi(p, q));
            // Get M = C^d mod d
            int M = (int)calc.FastPower(C, d, n);
            return M;
        }
    }
}
