
undefined8 FUN_180fd9220(longlong *param_1,longlong *param_2)

{
  longlong *plVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  longlong alStack_80 [7];
  longlong *plStack_48;
  undefined8 *puStack_40;
  void *pvStack_38;
  longlong *plStack_30;
  undefined8 uStack_28;
  
  uStack_28 = 0xfffffffffffffffe;
  plStack_48 = (longlong *)0x0;
  plVar1 = (longlong *)param_2[7];
  if (plVar1 != (longlong *)0x0) {
    if (plVar1 == param_2) {
      plStack_48 = (longlong *)(**(code **)(*plVar1 + 8))(plVar1,alStack_80);
      plVar1 = (longlong *)param_2[7];
      if (plVar1 == (longlong *)0x0) goto LAB_180fd9288;
      (**(code **)(*plVar1 + 0x20))(plVar1,plVar1 != param_2);
      plVar1 = plStack_48;
    }
    plStack_48 = plVar1;
    param_2[7] = 0;
  }
LAB_180fd9288:
  plStack_30 = param_2;
  puStack_40 = (undefined8 *)operator_new(0x50);
  puStack_40[1] = 0;
  *puStack_40 = &PTR_LAB_188b8d5e8;
  pvStack_38 = operator_new(0x40);
  *(undefined8 *)((longlong)pvStack_38 + 0x38) = 0;
  puVar3 = (undefined8 *)operator_new(0x48);
  *puVar3 = &PTR_LAB_188d44a58;
  puVar3[8] = 0;
  if (plStack_48 != (longlong *)0x0) {
    if (plStack_48 == alStack_80) {
      uVar4 = (**(code **)(*plStack_48 + 8))(plStack_48,puVar3 + 1);
      puVar3[8] = uVar4;
      if (plStack_48 == (longlong *)0x0) goto LAB_180fd932a;
      (**(code **)(*plStack_48 + 0x20))(plStack_48,plStack_48 != alStack_80);
    }
    else {
      puVar3[8] = plStack_48;
    }
    plStack_48 = (longlong *)0x0;
  }
LAB_180fd932a:
  puVar2 = puStack_40;
  *(undefined8 **)((longlong)pvStack_38 + 0x38) = puVar3;
  puStack_40[2] = pvStack_38;
  puStack_40[3] = pvStack_38;
  puStack_40[4] = &DAT_180389bc0;
  puStack_40[5] = &LAB_180389b60;
  puStack_40[6] = 0;
  *(undefined4 *)(puStack_40 + 7) = 0;
  puStack_40[8] = FUN_1802d2f80;
  uVar4 = (**(code **)(*(longlong *)param_1[1] + 0x18))();
  (**(code **)(*(longlong *)param_1[1] + 0x28))((longlong *)param_1[1],uVar4,0,puVar2,0,0);
  (**(code **)(*param_1 + 0x20))(param_1,uVar4,0,0,0);
  if (plStack_48 != (longlong *)0x0) {
    (**(code **)(*plStack_48 + 0x20))(plStack_48,plStack_48 != alStack_80);
  }
  plVar1 = (longlong *)plStack_30[7];
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x20))(plVar1,plVar1 != plStack_30);
  }
  return uVar4;
}

