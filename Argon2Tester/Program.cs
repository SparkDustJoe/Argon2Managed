using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Argon2Managed.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            if (!LoadBlakeTests())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Blake Tests ***FAIL***");
            }
            else
            {
                Console.WriteLine("Blake Tests ---PASS---");
            }
            if (!LoadArgon2Tests())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Argon2 Tests ***FAIL***");
            }
            else
            {
                Console.WriteLine("Argon2 Tests ---PASS---");
            }

            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static bool LoadBlakeTests()
        {
            string Input = null;
            string Key = null;
            string Result = null;
            string Type = null;
            bool AllGood = true;
            foreach (string line in Properties.Resources.TESTS.Split(new string[] { "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains("hash")) { Type = line; continue; }
                if (line.Contains("in")) { Input = line; continue; }
                if (line.Contains("out")) { Result = line; continue; }
                if (line.Contains("key")) { Key = line; continue; }

                if (Type != null && Input != null && Result != null & Key != null)
                {                
                    Input = Input.Substring(Input.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    Key = Key.Substring(Key.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    Result = Result.Substring(Result.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    byte[] KeyBytes = HexString2Bytes(Key);
                    byte[] InputBytes = HexString2Bytes(Input);
                    byte[] h = new byte[0];
                    if (Type.Contains("blake2s\""))
                    {
                        Console.Write("Testing " + Type + ", |Key|=" + KeyBytes.Length + " |Input|=" + InputBytes.Length + " |OutputLength|=" + (Result.Length / 2));
                        Blake2s b = new Blake2s(KeyBytes, (byte)(Result.Length / 2));
                        h = b.ComputeHash(InputBytes);
                    }
                    else if (Type.Contains("blake2b\""))
                    {
                        Console.Write("Testing " + Type + ", |Key|=" + KeyBytes.Length + " |Input|=" + InputBytes.Length + " |OutputLength|=" + (Result.Length / 2));
                        Blake2b b = new Blake2b(KeyBytes, (byte)(Result.Length / 2));
                        h = b.ComputeHash(InputBytes);
                    }
                    else
                    {
                        //Console.WriteLine("-SKIPPING-");
                        Type = Input = Result = Key = null;
                        continue;
                    }
                    if (BitConverter.ToString(h).Replace("-", "").ToLower() != Result)
                    {
                        Console.WriteLine("  **FAIL**");
                        AllGood = false;
                        break;
                    }
                    else
                        Console.WriteLine("  --PASS--");
                    Type = Input = Result = Key = null;
                }
            }


            return AllGood;
        }

        private struct argon_test
        {
            public UInt32 time;
            public UInt32 mem;
            public UInt32 lanes;
            public byte[] pass;
            public byte[] salt;
            public string hexResult;
            public byte[] ad;
            public byte[] secret; 
        }

        static bool LoadArgon2Tests()
        {
            //Console.WriteLine("Pausing 1 sec for command window...");
            //System.Threading.Thread.Sleep(1000);
            byte[] pass1 = ASCIIEncoding.ASCII.GetBytes("password");
            byte[] salt1 = ASCIIEncoding.ASCII.GetBytes("somesalt");
            argon_test[] tests = new argon_test[]
            {
                // the following are from the KATS in GitHub for the official repository
                new argon_test { time = 3, mem = 32, lanes=4,
                    pass = new byte[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 },
                    salt =  new byte[]{ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2},
                    hexResult = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
                    secret = new byte[]{ 3,3,3,3,3,3,3,3 },
                    ad = new byte[] { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 } },
                // the following are from the reference test program
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1 , hexResult = "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0", secret= null, ad=null},
#if HIGH_MEM
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,20), lanes=1, // this will consume a GB of storage for the process!!
                    pass = pass1, salt = salt1, hexResult = "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41", secret= null, ad=null},
#endif
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,18), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,8), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,8), lanes=2,
                    pass = pass1, salt = salt1, hexResult = "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61", secret= null, ad=null},
                new argon_test { time = 1, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf", secret= null, ad=null},
                new argon_test { time = 4, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = ASCIIEncoding.ASCII.GetBytes("differentpassword"), salt = salt1, hexResult = "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                    secret = null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = ASCIIEncoding.ASCII.GetBytes("diffsalt"), hexResult = "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
                    secret = null, ad=null}
            };

            string testhexresult;
            byte[] output;
            string outputString;
            int ret;
            System.Threading.Thread.Sleep(2000);
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            foreach (argon_test t in tests)
            {
                sw.Reset();
                outputString = null;
                output = null;
                Console.Write(string.Format("ARGON TEST t={0}, mem={1}, lanes={2}, result={3}, ", t.time, t.mem, t.lanes, t.hexResult));
                sw.Start();
                ret = Argon2.ComputeEncodedHash(t.pass, t.salt, 32, Argon2Type.i, t.secret, t.ad, t.time, t.mem, t.lanes, out output, out outputString);
                sw.Stop();
                Console.Write(" time taken: " + sw.Elapsed.ToString() + " ");
                testhexresult = Bytes2HexString(output);
                if (t.hexResult.CompareTo(testhexresult) != 0 || ret != 0)
                {
                    Console.WriteLine(" ***FAIL*** RET=" + Argon2.ErrorMessage(ret));
                    return false;
                }
                else
                {
                    GC.Collect();
                    ret = Argon2.VerifyEncodedHash(t.pass, t.secret, t.ad, outputString);
                    if ( ret != 0)
                    {
                        Console.WriteLine(" - COMPUTE PASS/ VERIFY FAIL**** RET=" + Argon2.ErrorMessage(ret));
                        return false;
                    }
                    else
                    {
                        Console.WriteLine(" -COMPUTE/VERIFY PASS- ");
                    }
                }
                GC.Collect();
            }

            return true;
        }

        static byte[] HexString2Bytes(string input)
        {
            byte[] output = new byte[input.Length / 2];
            for (int i = 0; i < input.Length; i+=2)
            {
                output[i / 2] = byte.Parse(input.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return output;
        }

        static string Bytes2HexString(byte[] input)
        {
            if (input == null) return "";
            string output = BitConverter.ToString(input).Replace("-", "").ToLower();
            return output;
        }
    }
}
