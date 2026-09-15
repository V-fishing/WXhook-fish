
undefined8
FUN_180d9e850(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
             ulonglong param_5)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar1 = param_5 >> 8 & 0xffffff;
  uVar2 = param_5 >> 8 & 0xffff04;
  FUN_180d9f920(param_1,0,0,CONCAT71((int7)(uVar2 >> 8),(byte)uVar2 >> 2),(byte)(uVar1 >> 5) & 7,
                param_2,(short)(param_5 >> 0x10),param_3,param_4,(int)(param_5 >> 0x20),
                (byte)(uVar1 >> 3) & 3);
  return param_1;
}

