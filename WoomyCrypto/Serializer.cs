using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WoomyCrypto
{
    public static class Serializer
    {
        public static T Deserialize<T>(byte[] buffer)
        {
            /* Pin data we're copying it. */
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            /* Copy data into struct. */
            T t = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            /* Unpin. */
            handle.Free();

            return t;
        }
    }
}
