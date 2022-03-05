using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WoomyCrypto
{
    [StructLayout(LayoutKind.Sequential, Size = BlitzAmiibo.MessageSize, CharSet = CharSet.Unicode)]
    public struct AmiiboData
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = BlitzAmiibo.PaddingSize)]
        public byte[] Padding;
        public int Sig;
        public int FieldC;
        public int WeaponId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = UnmanagedType.I4)]
        public int[] GearIds;
        public byte SquidPlayerModelType;
        public byte SquidSkinAndEyeColor;
        public byte SquidHairAndBottomIds;
        public byte PackedCtrlStick0;
        public byte PackedCtrlMotion0;
        public byte PackedCtrlStick1;
        public byte PackedCtrlMotion1;
        public byte PackedCtrls;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3 * 4, ArraySubType = UnmanagedType.U8)]
        public byte[] WeaponGearKillArray;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 10)]
        public string UserName;
        public byte OctoPlayerModelType;
        public byte OctoSkinAndEyeColor;
        public byte OctoHairAndBottomIds;
        public byte mIsOcto;
    }
}
