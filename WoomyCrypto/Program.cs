using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace WoomyCrypto
{
    class Program
    {
        enum Operation
        {
            Decrypt,
            Encrypt,
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Args: -d/-e [file path]");
                return;
            }

            Operation op;
            var opStr = args[0];
            switch (opStr)
            {
                case "-d":
                    op = Operation.Decrypt;
                    break;
                case "-e":
                    op = Operation.Encrypt;
                    break;
                default:
                    Console.WriteLine($"Invalid operation \"{opStr}\". Expected -d or -e.");
                    return;

            }

            var inputFi = new FileInfo(args[1]);

            if(!inputFi.Exists)
            {
                Console.WriteLine("File path does not exist.");
                return;
            }

            if (op == Operation.Decrypt)
            {
                if (inputFi.Length != BlitzAmiibo.TotalEncSize)
                {
                    Console.WriteLine($"File is not correct size. ({BlitzAmiibo.TotalEncSize:X8})");
                    return;
                }
            }
            else if (op == Operation.Encrypt)
            {
                if(inputFi.Length != BlitzAmiibo.MessageSize)
                {
                    Console.WriteLine($"File is not correct size. ({BlitzAmiibo.MessageSize:X8})");
                    return;
                }
            }

            var inputData = ReadAll(inputFi);

            MemeCtx meme = BlitzAmiibo.MakeCtx();

            byte[] output;
            uint outputSize;
            FileInfo outputFi;
            switch(op)
            {
                case Operation.Decrypt:
                    outputSize = BlitzAmiibo.MessageSize;
                    output = new byte[outputSize];
                    if (!meme.Verify(output, ref outputSize, inputData, BlitzAmiibo.TotalEncSize, 0x10))
                    {
                        Console.WriteLine("Failed to verify data! Output could be wrong.");
                    }
                    outputFi = new FileInfo(inputFi.FullName + ".dec");

                    var amiibo = Serializer.Deserialize<AmiiboData>(output);
                    ;
                    break;
                case Operation.Encrypt:
                    outputSize = BlitzAmiibo.PayloadSize + 0x10;
                    output = new byte[outputSize];
                    if (!meme.Sign(output, ref outputSize, inputData[..BlitzAmiibo.PayloadSize], 0x10))
                    {
                        Console.WriteLine("Failed to sign data! Output could be wrong.");
                    }
                    outputFi = new FileInfo(inputFi.FullName + ".enc");
                    break;
                default:
                    /* Unreachable. */
                    return;
            }

            WriteAll(outputFi, output);
        }

        static Span<byte> ReadAll(FileInfo fi)
        {
            Span<byte> data;

            using var r = fi.OpenRead();
            data = new byte[r.Length];
            r.Read(data);
            
            return data;
        }

        static void WriteAll(FileInfo fi, Span<byte> data)
        {
            using var w = fi.Create();
            w.Write(data);
        }

    }
}
