
void FUN_1872f2670(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  HMODULE pHVar2;
  int *piVar3;
  undefined4 local_res10 [2];
  int local_res18 [2];
  undefined1 local_res20 [8];
  undefined1 local_38 [4];
  undefined4 local_34;
  undefined4 local_30 [2];
  undefined8 local_28;
  undefined4 *local_20;
  int *local_18;
  undefined1 *local_10;
  
  local_28 = 0xfffffffffffffffe;
  local_res10[0] = param_2;
  local_res18[0] = param_3;
  if (param_3 == 0) {
    pHVar2 = GetModuleHandleW((LPCWSTR)0x0);
    if ((((pHVar2 != (HMODULE)0x0) && ((short)pHVar2->unused == 0x5a4d)) &&
        (piVar3 = (int *)((longlong)&pHVar2->unused + (longlong)pHVar2[0xf].unused),
        *piVar3 == 0x4550)) &&
       ((((short)piVar3[6] == 0x20b && (0xe < (uint)piVar3[0x21])) && (piVar3[0x3e] != 0)))) {
      FUN_1872f25a8(param_1);
    }
  }
  local_res20[0] = 0;
  local_20 = local_res10;
  local_18 = local_res18;
  local_10 = local_res20;
  local_34 = 2;
  local_30[0] = 2;
  operator()<>(local_38,local_30,&local_20,&local_34);
  if (local_res18[0] != 0) {
    return;
  }
  FUN_1872f263c(param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

