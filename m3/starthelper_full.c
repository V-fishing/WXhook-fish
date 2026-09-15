
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1804640d0(longlong param_1)

{
  longlong lVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined4 uVar5;
  char cVar6;
  undefined1 uVar7;
  DWORD DVar8;
  longlong *plVar9;
  undefined8 uVar10;
  longlong lVar11;
  longlong *local_198 [7];
  undefined1 local_160 [64];
  undefined8 *****local_120 [3];
  ulonglong local_108;
  ulonglong local_a8;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  longlong local_98;
  undefined4 local_90;
  undefined4 uStack_8c;
  ulonglong uStack_88;
  ulonglong local_80;
  undefined8 uStack_78;
  undefined4 local_70;
  undefined4 uStack_6c;
  ulonglong uStack_68;
  undefined8 local_60;
  undefined8 local_50;
  
  local_50 = 0xfffffffffffffffe;
  cVar6 = FUN_180d9e810(0);
  if (cVar6 != '\0') {
    FUN_180d9e850(local_198,&DAT_188b7ed18,"do_resume_now","co_core.cpp",0x18f00000800);
    local_a8 = CONCAT44(local_a8._4_4_,*(undefined4 *)(param_1 + 0x388));
    plVar9 = local_198[0] + 0xf;
    if (0xf < (ulonglong)local_198[0][0x12]) {
      plVar9 = (longlong *)*plVar9;
    }
    FUN_1804657f0(local_198[0] + 7,"coroutine resume : id %_, name \"%_\", status %_, is_active %_",
                  plVar9,param_1 + 0x4a0,param_1 + 0x4a8,&local_a8,param_1 + 0x4f8);
    FUN_180d9e8e0();
    FUN_180d9e8f0(local_198);
  }
  if (*(int *)(param_1 + 0x388) == 2) {
    DVar8 = GetCurrentThreadId();
    if (*(DWORD *)(param_1 + 0x4c8) != DVar8) {
      FUN_180d9e850(local_198,&DAT_188b7ed18,"do_resume_now","co_core.cpp",0x1c20000b000);
      uVar3 = _DAT_188ad27c0;
      if (local_108 < 0x10) {
        local_120[0] = local_120;
      }
      uStack_9c = (undefined4)(_UNK_188ad27c8 >> 0x20);
      uVar5 = uStack_9c;
      _uStack_a0 = CONCAT44(uStack_9c,6);
      local_a8 = _DAT_188ad27c0 & 0xffffffff00000000;
      FUN_180d9f220(local_160,"Fatal error: ",local_120[0],&local_a8,0);
      plVar9 = local_198[0] + 0xf;
      if (0xf < (ulonglong)local_198[0][0x12]) {
        plVar9 = (longlong *)*plVar9;
      }
      _uStack_a0 = CONCAT44(uVar5,6);
      local_a8 = uVar3 & 0xffffffff00000000;
      FUN_180d9f220(local_198[0] + 7,"resume coroutine in a different thread is not allowed",plVar9,
                    &local_a8,0);
      FUN_180d9e8e0();
      FUN_180d9e8f0(local_198);
      return;
    }
    cVar6 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x18))();
    if (cVar6 != '\0') {
      FUN_180465280(param_1);
    }
    *(undefined4 *)(param_1 + 0x388) = 1;
    local_198[0] = (longlong *)0x0;
    lVar11 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
    uVar10 = *(undefined8 *)(lVar11 + 0x1f0);
    uVar2 = *(undefined8 *)(lVar11 + 0x1f8);
    *(longlong *)(lVar11 + 0x1f0) = param_1;
    *(undefined8 *)(lVar11 + 0x1f8) = *(undefined8 *)(param_1 + 0x4a0);
    FUN_18000afb0(local_198,*(undefined8 *)(param_1 + 0x330),*(undefined8 *)(param_1 + 0x338));
    FUN_181105ed0(param_1 + 0x10,param_1 + 0x1b0);
    FUN_18000afb0(local_198[0]);
    *(undefined8 *)(lVar11 + 0x1f0) = uVar10;
    *(undefined8 *)(lVar11 + 0x1f8) = uVar2;
  }
  else {
    if (*(int *)(param_1 + 0x388) != 0) {
      FUN_180d9e850(local_198,&DAT_188b7ed18,"do_resume_now","co_core.cpp",0x1db0000b000);
      uStack_88 = _UNK_188ad27c8;
      uVar3 = _DAT_188ad27c0;
      if (local_108 < 0x10) {
        local_120[0] = local_120;
      }
      uStack_9c = (undefined4)(_UNK_188ad27c8 >> 0x20);
      _uStack_a0 = CONCAT44(uStack_9c,6);
      local_a8 = _DAT_188ad27c0 & 0xffffffff00000000;
      FUN_180d9f220(local_160,"Fatal error: ",local_120[0],&local_a8,0);
      plVar9 = local_198[0] + 0xf;
      if (0xf < (ulonglong)local_198[0][0x12]) {
        plVar9 = (longlong *)*plVar9;
      }
      local_a8 = *(ulonglong *)(param_1 + 0x4a0);
      uStack_9c = (undefined4)(uVar3 >> 0x20);
      _uStack_a0 = CONCAT44(uStack_9c,0xb);
      _local_90 = CONCAT44(uStack_9c,0x10);
      if (*(ulonglong *)(param_1 + 0x4c0) < 0x10) {
        local_98 = param_1 + 0x4a8;
      }
      else {
        local_98 = *(longlong *)(param_1 + 0x4a8);
      }
      local_80 = 0xaaaaaaaa00000006;
      uStack_88 = uStack_88 & 0xffffffff00000000;
      FUN_180d9f220(local_198[0] + 7,"coroutine is already running: id %_, name \"%_\"",plVar9,
                    &local_a8,2);
      FUN_180d9e8e0();
      FUN_180d9e8f0(local_198);
      goto LAB_18046474d;
    }
    plVar9 = *(longlong **)(param_1 + 0x370);
    if (plVar9 == (longlong *)0x0) {
      plVar9 = (longlong *)FUN_18045fa30();
      *(longlong **)(param_1 + 0x370) = plVar9;
      if (*(longlong *)(param_1 + 0x380) != 0) goto LAB_18046442d;
LAB_18046443e:
      uVar10 = (**(code **)(*plVar9 + 0x20))();
      *(undefined8 *)(param_1 + 0x380) = uVar10;
    }
    else {
      if (*(longlong *)(param_1 + 0x380) == 0) goto LAB_18046443e;
LAB_18046442d:
      cVar6 = (**(code **)(*plVar9 + 0x18))();
      if (cVar6 != '\0') {
        plVar9 = *(longlong **)(param_1 + 0x370);
        goto LAB_18046443e;
      }
      uVar10 = *(undefined8 *)(param_1 + 0x380);
    }
    lVar11 = (**(code **)(**(longlong **)(param_1 + 0x370) + 8))
                       (*(longlong **)(param_1 + 0x370),uVar10);
    *(longlong *)(param_1 + 0x378) = lVar11;
    if (0xfffffffffffffffd < lVar11 - 1U) {
      FUN_180d9e850(local_198,&DAT_188b7ed18,"do_resume_now","co_core.cpp",0x19c0000b000);
      uVar4 = _UNK_188ad27c8;
      uVar3 = _DAT_188ad27c0;
      if (local_108 < 0x10) {
        local_120[0] = local_120;
      }
      uStack_9c = (undefined4)(_UNK_188ad27c8 >> 0x20);
      uVar5 = uStack_9c;
      _uStack_a0 = CONCAT44(uStack_9c,6);
      local_a8 = _DAT_188ad27c0 & 0xffffffff00000000;
      FUN_180d9f220(local_160,"Fatal error: ",local_120[0],&local_a8,0);
      plVar9 = local_198[0] + 0xf;
      if (0xf < (ulonglong)local_198[0][0x12]) {
        plVar9 = (longlong *)*plVar9;
      }
      _uStack_a0 = CONCAT44(uVar5,6);
      local_a8 = uVar3 & 0xffffffff00000000;
      FUN_180d9f220(local_198[0] + 7,"%@() alloc coroutine stack failed, ",plVar9,&local_a8,0);
      lVar11 = *local_198[0];
      uVar10 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x20))();
      uVar7 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x18))();
      plVar9 = (longlong *)(lVar11 + 0x78);
      if (0xf < *(ulonglong *)(lVar11 + 0x90)) {
        plVar9 = (longlong *)*plVar9;
      }
      local_a8 = *(ulonglong *)(param_1 + 0x378);
      uStack_9c = (undefined4)(uVar3 >> 0x20);
      _uStack_a0 = CONCAT44(uStack_9c,0xf);
      local_98 = *(longlong *)(param_1 + 0x380);
      _local_90 = CONCAT44(uStack_9c,0xb);
      local_80 = uVar3 & 0xffffffff00000000;
      uStack_88 = CONCAT71((int7)(uVar4 >> 8),uVar7);
      _local_70 = CONCAT44(uStack_9c,0xb);
      local_60 = 0xaaaaaaaa00000006;
      uStack_68 = uVar4 & 0xffffffff00000000;
      uStack_78 = uVar10;
      FUN_180d9f220(lVar11 + 0x38,
                    "stack_base_ = %_, stack_size_ = %_, alloc_->is_shared() = %_, alloc_->block_size() = %_"
                    ,plVar9,&local_a8,4);
      FUN_180d9e8e0();
      FUN_180d9e8f0(local_198);
    }
    cVar6 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x18))();
    if (cVar6 == '\0') {
      FUN_18057c2a0(*(undefined8 *)(param_1 + 0x378),*(undefined8 *)(param_1 + 0x380));
    }
    lVar11 = param_1 + 0x1b0;
    FUN_187173820(lVar11);
    *(undefined8 *)(param_1 + 0x330) = *(undefined8 *)(param_1 + 0x378);
    *(undefined8 *)(param_1 + 0x338) = *(undefined8 *)(param_1 + 0x380);
    *(longlong *)(param_1 + 0x340) = param_1 + 0x10;
    DVar8 = GetCurrentThreadId();
    *(DWORD *)(param_1 + 0x4c8) = DVar8;
    *(undefined4 *)(param_1 + 0x388) = 1;
    local_198[0] = (longlong *)0x0;
    lVar1 = *(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8);
    uVar10 = *(undefined8 *)(lVar1 + 0x1f0);
    uVar2 = *(undefined8 *)(lVar1 + 0x1f8);
    *(longlong *)(lVar1 + 0x1f0) = param_1;
    *(undefined8 *)(lVar1 + 0x1f8) = *(undefined8 *)(param_1 + 0x4a0);
    FUN_181105f00(lVar11,FUN_180464950,param_1);
    FUN_18000afb0(local_198,*(undefined8 *)(param_1 + 0x330),*(undefined8 *)(param_1 + 0x338));
    FUN_181105ed0(param_1 + 0x10,lVar11);
    FUN_18000afb0(local_198[0]);
    *(undefined8 *)(lVar1 + 0x1f0) = uVar10;
    *(undefined8 *)(lVar1 + 0x1f8) = uVar2;
  }
  cVar6 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x18))();
  if ((cVar6 != '\0') && (*(int *)(param_1 + 0x388) != 3)) {
    FUN_180464ed0(param_1);
  }
LAB_18046474d:
  if (*(int *)(param_1 + 0x388) == 3) {
    cVar6 = (**(code **)(**(longlong **)(param_1 + 0x370) + 0x18))();
    if (cVar6 == '\0') {
      FUN_18057c750(*(undefined8 *)(param_1 + 0x378),*(undefined8 *)(param_1 + 0x380));
    }
    FUN_180465440(param_1);
  }
  return;
}

