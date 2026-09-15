
void FUN_1872e5568(longlong param_1)

{
  int *piVar1;
  string_output_adapter<char> *this;
  undefined2 uVar2;
  uint uVar3;
  bool bVar4;
  char cVar5;
  longlong lVar6;
  int iVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  undefined2 *puVar11;
  longlong lVar12;
  undefined1 auStackY_78 [32];
  undefined4 local_48;
  char local_44 [12];
  ulonglong local_38;
  
  local_38 = DAT_18adb3f00 ^ (ulonglong)auStackY_78;
  cVar8 = 'x';
  cVar5 = *(char *)(param_1 + 0x39);
  lVar12 = 1;
  if (cVar5 < 'e') {
    if (cVar5 == 'd') {
LAB_1872e5647:
      *(uint *)(param_1 + 0x28) = *(uint *)(param_1 + 0x28) | 0x10;
LAB_1872e564b:
      cVar5 = FUN_1872e7c78(param_1);
    }
    else if (cVar5 < 'T') {
      if (cVar5 == 'S') {
LAB_1872e568e:
        cVar5 = FUN_1872e5abc(param_1);
      }
      else {
        if (cVar5 != 'A') {
          if (cVar5 == 'C') {
LAB_1872e5601:
            cVar5 = FUN_1872e596c(param_1);
            goto LAB_1872e56b1;
          }
          if (((cVar5 != 'E') && (cVar5 != 'F')) && (cVar5 != 'G')) goto LAB_1872e593f;
        }
LAB_1872e55d8:
        cVar5 = FUN_1872e5b58(param_1);
      }
    }
    else {
      if (cVar5 == 'X') goto LAB_1872e56a9;
      if (cVar5 != 'Z') {
        if (cVar5 != 'a') {
          if (cVar5 != 'c') goto LAB_1872e593f;
          goto LAB_1872e5601;
        }
        goto LAB_1872e55d8;
      }
      cVar5 = FUN_1872e5a40(param_1);
    }
  }
  else if (cVar5 < 'p') {
    if (cVar5 == 'o') {
      if ((*(uint *)(param_1 + 0x28) >> 5 & 1) != 0) {
        *(uint *)(param_1 + 0x28) = *(uint *)(param_1 + 0x28) | 0x80;
      }
      cVar5 = FUN_1872e7a74(param_1);
    }
    else {
      if (((cVar5 == 'e') || (cVar5 == 'f')) || (cVar5 == 'g')) goto LAB_1872e55d8;
      if (cVar5 == 'i') goto LAB_1872e5647;
      if (cVar5 != 'n') goto LAB_1872e593f;
      cVar5 = FUN_1872e5dac(param_1);
    }
  }
  else {
    if (cVar5 == 'p') {
      *(undefined4 *)(param_1 + 0x30) = 0x10;
      *(undefined4 *)(param_1 + 0x34) = 0xb;
    }
    else {
      if (cVar5 == 's') goto LAB_1872e568e;
      if (cVar5 == 'u') goto LAB_1872e564b;
      if (cVar5 != 'x') goto LAB_1872e593f;
    }
LAB_1872e56a9:
    cVar5 = FUN_1872e7870(param_1);
  }
LAB_1872e56b1:
  if ((cVar5 != '\0') && (*(char *)(param_1 + 0x38) == '\0')) {
    uVar3 = *(uint *)(param_1 + 0x28);
    local_48 = local_48 & 0xff000000;
    lVar6 = 0;
    if ((uVar3 >> 4 & 1) != 0) {
      if ((uVar3 >> 6 & 1) == 0) {
        if ((uVar3 & 1) == 0) {
          if ((uVar3 >> 1 & 1) != 0) {
            local_48 = CONCAT31(local_48._1_3_,0x20);
            lVar6 = lVar12;
          }
        }
        else {
          local_48 = CONCAT31(local_48._1_3_,0x2b);
          lVar6 = lVar12;
        }
      }
      else {
        local_48 = CONCAT31(local_48._1_3_,0x2d);
        lVar6 = lVar12;
      }
    }
    cVar5 = *(char *)(param_1 + 0x39);
    if (((cVar5 + 0xa8U & 0xdf) == 0) && ((uVar3 >> 5 & 1) != 0)) {
      bVar4 = true;
    }
    else {
      bVar4 = false;
    }
    if ((bVar4) || ((cVar5 + 0xbfU & 0xdf) == 0)) {
      local_44[lVar6 + -4] = '0';
      if ((cVar5 == 'X') || (cVar5 == 'A')) {
        cVar8 = 'X';
      }
      local_44[lVar6 + -3] = cVar8;
      lVar6 = lVar6 + 2;
    }
    iVar7 = (*(int *)(param_1 + 0x2c) - (int)lVar6) - *(int *)(param_1 + 0x48);
    if (((uVar3 & 0xc) == 0) && (iVar10 = 0, 0 < iVar7)) {
      iVar9 = *(int *)(param_1 + 0x20);
      do {
        lVar12 = *(longlong *)(param_1 + 0x460);
        if (*(longlong *)(lVar12 + 0x10) == *(longlong *)(lVar12 + 8)) {
          if (*(char *)(lVar12 + 0x18) == '\0') {
            iVar9 = -1;
          }
          else {
            iVar9 = iVar9 + 1;
          }
          *(int *)(param_1 + 0x20) = iVar9;
        }
        else {
          *(int *)(param_1 + 0x20) = iVar9 + 1;
          *(longlong *)(lVar12 + 0x10) = *(longlong *)(lVar12 + 0x10) + 1;
          *(undefined1 *)**(undefined8 **)(param_1 + 0x460) = 0x20;
          **(longlong **)(param_1 + 0x460) = **(longlong **)(param_1 + 0x460) + 1;
        }
        iVar9 = *(int *)(param_1 + 0x20);
      } while ((iVar9 != -1) && (iVar10 = iVar10 + 1, iVar10 < iVar7));
    }
    piVar1 = (int *)(param_1 + 0x20);
    this = (string_output_adapter<char> *)(param_1 + 0x460);
    __crt_stdio_output::string_output_adapter<char>::write_string
              (this,(char *)&local_48,(int)lVar6,piVar1,
               *(__crt_deferred_errno_cache **)(param_1 + 8));
    if (((*(uint *)(param_1 + 0x28) >> 3 & 1) != 0) &&
       (((*(uint *)(param_1 + 0x28) >> 2 & 1) == 0 && (iVar10 = 0, 0 < iVar7)))) {
      iVar9 = *piVar1;
      do {
        lVar12 = *(longlong *)this;
        if (*(longlong *)(lVar12 + 0x10) == *(longlong *)(lVar12 + 8)) {
          if (*(char *)(lVar12 + 0x18) == '\0') {
            iVar9 = -1;
          }
          else {
            iVar9 = iVar9 + 1;
          }
          *piVar1 = iVar9;
        }
        else {
          *piVar1 = iVar9 + 1;
          *(longlong *)(lVar12 + 0x10) = *(longlong *)(lVar12 + 0x10) + 1;
          *(undefined1 *)**(undefined8 **)this = 0x30;
          **(longlong **)this = **(longlong **)this + 1;
        }
        iVar9 = *piVar1;
      } while ((iVar9 != -1) && (iVar10 = iVar10 + 1, iVar10 < iVar7));
    }
    if ((*(char *)(param_1 + 0x4c) == '\0') || (*(int *)(param_1 + 0x48) < 1)) {
      __crt_stdio_output::string_output_adapter<char>::write_string
                (this,*(char **)(param_1 + 0x40),*(int *)(param_1 + 0x48),piVar1,
                 *(__crt_deferred_errno_cache **)(param_1 + 8));
    }
    else {
      puVar11 = *(undefined2 **)(param_1 + 0x40);
      iVar10 = 0;
      do {
        uVar2 = *puVar11;
        local_48 = 0;
        puVar11 = puVar11 + 1;
        iVar9 = FUN_187322070(&local_48,local_44,6,uVar2);
        if ((iVar9 != 0) || (local_48 == 0)) {
          *piVar1 = -1;
          break;
        }
        __crt_stdio_output::string_output_adapter<char>::write_string
                  (this,local_44,local_48,piVar1,*(__crt_deferred_errno_cache **)(param_1 + 8));
        iVar10 = iVar10 + 1;
      } while (iVar10 != *(int *)(param_1 + 0x48));
    }
    iVar10 = *piVar1;
    if (((-1 < iVar10) && ((*(uint *)(param_1 + 0x28) >> 2 & 1) != 0)) && (iVar9 = 0, 0 < iVar7)) {
      do {
        lVar12 = *(longlong *)this;
        if (*(longlong *)(lVar12 + 0x10) == *(longlong *)(lVar12 + 8)) {
          if (*(char *)(lVar12 + 0x18) == '\0') {
            iVar10 = -1;
          }
          else {
            iVar10 = iVar10 + 1;
          }
          *piVar1 = iVar10;
        }
        else {
          *piVar1 = iVar10 + 1;
          *(longlong *)(lVar12 + 0x10) = *(longlong *)(lVar12 + 0x10) + 1;
          *(undefined1 *)**(undefined8 **)this = 0x20;
          **(longlong **)this = **(longlong **)this + 1;
        }
        iVar10 = *piVar1;
      } while ((iVar10 != -1) && (iVar9 = iVar9 + 1, iVar9 < iVar7));
    }
  }
LAB_1872e593f:
  FUN_187165bb0(local_38 ^ (ulonglong)auStackY_78);
  return;
}

