using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WoomyCrypto
{
    class BlitzAmiibo
    {
        public const string NString = @"
            b3:ba:54:ae:8a:ec:e3:89:f8:10:40:7d:50:7d:e1:c5:
            c7:b2:c1:37:20:c3:81:ba:e7:21:8f:1e:10:d6:49:08:
            78:07:1b:10:32:f2:e8:24:b8:86:c8:20:44:fb:19:f2:
            69:0b:7a:d8:19:f0:b5:21:31:01:6a:4e:6a:65:32:dd:
            a3:e4:8f:d4:ad:75:db:21:39:cb:c0:8c:8c:f4:84:91:
            28:34:8e:6c:9b:be:d4:7b:d6:96:5d:79:f8:1c:46:7d:
            8b:e2:42:93:39:b9:51:6a:9f:42:55:e6:90:16:33:4c:
            e9:85:d8:cc:46:c2:e0:7f:ff:ad:e5:99:e3:e1:68:b4:
            25:02:05:a4:1e:5a:10:f2:23:4b:f3:54:1b:cc:f9:d6:
            59:ac:ef:4a:f8:c7:ce:b7:fd:60:af:55:3e:b2:c1:c9:
            b9:a2:0a:48:1d:63:fd:b3:cf:12:2b:7d:d5:b6:7e:71:
            1f:56:f9:01:2b:52:59:5f:d1:b9:54:71:01:ef:cc:c9
        ";

        public const string DString = @"
            58:93:8d:66:94:4b:59:7c:c6:c7:e3:b0:9e:f9:db:4a:
            69:38:1c:e7:79:7b:41:35:86:f1:d0:22:06:34:45:bc:
            29:c3:7e:c0:06:0c:17:02:f9:fa:5b:29:24:36:08:bc:
            a2:ae:a8:b5:56:5b:7e:39:44:78:a9:16:ca:72:e3:95:
            be:4f:47:df:8e:39:96:6c:92:9a:6b:64:19:97:ec:b9:
            c9:71:d5:7b:8b:6a:8a:38:1a:32:f3:10:c8:89:ce:e6:
            ff:00:57:48:30:dd:5c:db:aa:4a:d0:41:cc:e5:cd:1b:
            e6:9a:c2:03:f0:e2:0d:42:5a:35:83:cf:16:fe:48:d7:
            e5:6b:d6:83:e5:0f:99:dd:32:74:47:1a:d9:ff:5f:5d:
            fa:4a:d8:66:5e:00:78:fa:90:45:41:5f:fc:96:ad:87:
            0b:e0:b2:e0:0c:8b:d9:1b:fb:18:54:53:ab:9c:72:47:
            e8:2f:0d:79:44:53:b1:0c:8a:16:89:24:58:e6:09:2d
        ";

        public const string EString = "01:00:01";

        public const int PayloadSize = 184;
        public const int PaddingSize = 8;
        public const int MessageSize = PayloadSize + PaddingSize;
        public const int HashSize = 16;
        public const int TotalEncSize = MessageSize + PaddingSize;
        private static byte[] DecodeKeyString(string str)
        {
            var arry = new byte[str.Count(c => c == ':') + 1];

            var state = 0;
            var index = 0;
            byte b = 0;
            foreach (var c in str)
            {
                /* Are we expecting a digit? */
                if (state < 2)
                {
                    /* Filter out anything not alphanumeric. */
                    if (!char.IsLetterOrDigit(c))
                        continue;

                    /* Convert single digit to a byte. */
                    var num = (byte)Uri.FromHex(c);

                    /* If on the upper digit, shift it up. */
                    if (state == 0)
                        num <<= 4;

                    /* Copy digit into temp byte. */
                    b |= num;

                    /* Move to the next state. */
                    state++;
                }
                else
                {
                    /* Store temp byte. */
                    arry[index] = b;
                    index++;
                    /* Reset state. */
                    b = 0;
                    state = 0;
                }
            }

            /* Store the last decoded byte, if needed. */
            if(state != 0)
                arry[^1] = b;

            return arry;
        }

        public static MemeCtx MakeCtx()
        {
            return new(
                HashAlgorithmName.SHA256,
                DecodeKeyString(NString),
                DecodeKeyString(DString),
                DecodeKeyString(EString),
                MessageSize
            );
        }
    }
}
