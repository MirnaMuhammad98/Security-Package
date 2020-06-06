using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            NumberTheory calc = new NumberTheory();
            // q: prime number
            // alpha: primitive root of q
            // UserA Key Generation
            long ya = calc.FastPower(alpha, xa, q);
            // UserB Key Generation
            long yb = calc.FastPower(alpha, xb, q);

            List<int> keys = new List<int>
            {
                // Secret Key by User A
                (int)(calc.FastPower(yb, xa, q)),
                // Secret Key by User B
                (int)(calc.FastPower(ya, xb, q))
            };
            return keys;
        }
    }
}
