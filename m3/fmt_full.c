
undefined8 FUN_18730c1d4(uint param_1)

{
  code *pcVar1;
  bool bVar2;
  ulong *puVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 uVar6;
  byte bVar7;
  longlong lVar8;
  ulonglong uVar9;
  ulonglong *puVar10;
  longlong *plVar11;
  undefined4 local_res10;
  longlong *plVar12;
  
  plVar12 = (longlong *)0x0;
  plVar11 = (longlong *)0x0;
  local_res10 = 0;
  bVar2 = true;
  if (param_1 == 2) {
LAB_18730c22b:
    if (param_1 == 2) {
      puVar10 = &DAT_18b648f70;
    }
    else if (param_1 == 6) {
LAB_18730c2cd:
      puVar10 = &DAT_18b648f80;
      plVar11 = plVar12;
    }
    else if (param_1 == 0xf) {
      puVar10 = (ulonglong *)&DAT_18b648f88;
    }
    else if (param_1 == 0x15) {
      puVar10 = (ulonglong *)&DAT_18b648f78;
      plVar11 = plVar12;
    }
    else {
      if (param_1 == 0x16) goto LAB_18730c2cd;
      puVar10 = (ulonglong *)0x0;
      plVar11 = plVar12;
    }
  }
  else {
    if (param_1 != 4) {
      if (param_1 != 6) {
        if ((param_1 == 8) || (param_1 == 0xb)) goto LAB_18730c25b;
        if ((param_1 != 0xf) && ((param_1 != 0x15 && (param_1 != 0x16)))) goto LAB_18730c2ad;
      }
      goto LAB_18730c22b;
    }
LAB_18730c25b:
    plVar11 = (longlong *)FUN_18731da94();
    if (plVar11 == (longlong *)0x0) {
      return 0xffffffff;
    }
    lVar5 = *plVar11;
    lVar4 = DAT_1899a4920 * 0x10 + lVar5;
    for (; lVar5 != lVar4; lVar5 = lVar5 + 0x10) {
      if (*(uint *)(lVar5 + 4) == param_1) goto LAB_18730c2a8;
    }
    lVar5 = 0;
LAB_18730c2a8:
    if (lVar5 == 0) {
LAB_18730c2ad:
      puVar3 = __doserrno();
      *puVar3 = 0x16;
      FUN_1872f7b8c();
      return 0xffffffff;
    }
    puVar10 = (ulonglong *)(lVar5 + 8);
    bVar2 = false;
  }
  lVar5 = 0;
  if (bVar2) {
    FID_conflict___acrt_lock(3);
  }
  uVar9 = *puVar10;
  if (bVar2) {
    bVar7 = (byte)DAT_18adb3f00 & 0x3f;
    uVar9 = (uVar9 ^ DAT_18adb3f00) >> bVar7 | (uVar9 ^ DAT_18adb3f00) << 0x40 - bVar7;
  }
  if (uVar9 == 1) goto LAB_18730c3b6;
  if (uVar9 == 0) {
    if (bVar2) {
      FID_conflict___acrt_lock(3);
    }
    FUN_1872f2584(3);
    pcVar1 = (code *)swi(3);
    uVar6 = (*pcVar1)();
    return uVar6;
  }
  if ((param_1 < 0xc) && ((0x910U >> (param_1 & 0x1f) & 1) != 0)) {
    lVar5 = plVar11[1];
    plVar11[1] = 0;
    if (param_1 == 8) {
      lVar4 = FUN_18731d91c();
      local_res10 = *(undefined4 *)(lVar4 + 0x10);
      lVar4 = FUN_18731d91c();
      *(undefined4 *)(lVar4 + 0x10) = 0x8c;
      goto LAB_18730c36e;
    }
  }
  else {
LAB_18730c36e:
    if (param_1 == 8) {
      lVar4 = DAT_1899a4930 * 0x10 + *plVar11;
      lVar8 = DAT_1899a4938 * 0x10 + lVar4;
      for (; lVar4 != lVar8; lVar4 = lVar4 + 0x10) {
        *(undefined8 *)(lVar4 + 8) = 0;
      }
      goto LAB_18730c3b6;
    }
  }
  *puVar10 = DAT_18adb3f00;
LAB_18730c3b6:
  if (bVar2) {
    FID_conflict___acrt_lock(3);
  }
  if (uVar9 != 1) {
    if (param_1 == 8) {
      lVar4 = FUN_18731d91c();
      (*(code *)PTR__guard_dispatch_icall_1899b7a70)(8,*(undefined4 *)(lVar4 + 0x10));
    }
    else {
      (*(code *)PTR__guard_dispatch_icall_1899b7a70)(param_1);
    }
    if (((param_1 < 0xc) && ((0x910U >> (param_1 & 0x1f) & 1) != 0)) &&
       (plVar11[1] = lVar5, param_1 == 8)) {
      lVar5 = FUN_18731d91c();
      *(undefined4 *)(lVar5 + 0x10) = local_res10;
    }
  }
  return 0;
}

