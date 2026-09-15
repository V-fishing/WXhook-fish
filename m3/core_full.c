
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_181795500(longlong param_1,undefined8 *param_2)

{
  longlong *plVar1;
  int *piVar2;
  undefined8 *****pppppuVar3;
  undefined1 uVar4;
  code *pcVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  longlong *plVar9;
  char cVar10;
  int iVar11;
  uint uVar12;
  ulonglong uVar13;
  ulonglong *****pppppuVar14;
  undefined8 uVar15;
  ulonglong uVar16;
  undefined8 ******ppppppuVar17;
  undefined8 *puVar18;
  ulonglong uVar19;
  void *pvVar20;
  void *pvVar21;
  undefined8 ******ppppppuVar22;
  undefined1 *puVar23;
  undefined8 *******pppppppuVar24;
  ulonglong *******pppppppuVar25;
  longlong lVar26;
  ulonglong uVar27;
  longlong lVar28;
  ulonglong *******pppppppuVar29;
  longlong *plVar30;
  undefined1 *puVar31;
  ulonglong uVar32;
  undefined8 *******pppppppuVar33;
  longlong *plVar34;
  longlong lVar35;
  longlong lVar36;
  bool bVar37;
  undefined1 local_470 [56];
  undefined8 *local_438;
  undefined8 *******local_430;
  undefined1 local_428;
  ulonglong local_418;
  undefined **local_3e0;
  longlong local_3d8;
  longlong *local_3d0;
  longlong local_3c8;
  undefined ***local_3a8;
  undefined8 *******local_3a0 [3];
  ulonglong local_388;
  undefined8 *******local_380 [3];
  ulonglong local_368;
  undefined8 ******local_360;
  ulonglong ******local_358;
  ulonglong ******ppppppuStack_350;
  ulonglong *******local_348;
  ulonglong uStack_340;
  ulonglong *******local_338;
  longlong *plStack_330;
  undefined8 ******local_328;
  undefined8 *local_320;
  longlong local_318;
  longlong *plStack_310;
  longlong local_308;
  longlong *plStack_300;
  longlong local_2f8;
  longlong *plStack_2f0;
  longlong local_2e8;
  longlong *plStack_2e0;
  longlong local_2d8;
  longlong *plStack_2d0;
  longlong local_2c8;
  undefined8 *******local_2c0;
  undefined8 uStack_2b8;
  ulonglong local_2b0;
  ulonglong uStack_2a8;
  undefined8 local_248;
  undefined8 local_240;
  ulonglong local_230;
  undefined8 local_1f8;
  undefined8 uStack_1f0;
  ulonglong local_1e0;
  undefined8 local_1a8;
  undefined8 local_1a0;
  ulonglong local_190;
  undefined8 local_158;
  ulonglong *******pppppppuStack_150;
  undefined8 ******local_148;
  ulonglong *******pppppppuStack_140;
  undefined8 ******local_138;
  ulonglong *******pppppppuStack_130;
  longlong *local_128;
  undefined8 *******local_118;
  undefined8 *puStack_110;
  undefined8 *local_108;
  undefined8 *puStack_100;
  undefined8 local_f8;
  undefined8 uStack_f0;
  undefined8 local_e8;
  undefined8 uStack_e0;
  undefined8 local_d8;
  undefined8 uStack_d0;
  undefined8 local_c8;
  undefined8 uStack_c0;
  undefined8 local_b8;
  undefined8 uStack_b0;
  undefined8 local_a8;
  undefined8 uStack_a0;
  undefined8 *local_90;
  longlong local_88;
  longlong *plStack_80;
  longlong local_78;
  longlong *plStack_70;
  undefined1 local_61;
  undefined8 local_60;
  
  local_60 = 0xfffffffffffffffe;
  uVar13 = param_2[2];
  puVar18 = param_2;
  if (0xf < (ulonglong)param_2[3]) {
    puVar18 = (undefined8 *)*param_2;
  }
  lVar36 = *(longlong *)(param_1 + 0xbf8);
  if (uVar13 == 0) {
    uVar27 = 0xcbf29ce484222325;
  }
  else {
    uVar16 = (ulonglong)((uint)uVar13 & 3);
    if (uVar13 < 4) {
      uVar27 = 0xcbf29ce484222325;
      uVar19 = 0;
    }
    else {
      uVar27 = 0xcbf29ce484222325;
      uVar19 = 0;
      do {
        uVar27 = ((ulonglong)*(byte *)((longlong)puVar18 + uVar19 + 3) ^
                 ((ulonglong)*(byte *)((longlong)puVar18 + uVar19 + 2) ^
                 ((ulonglong)*(byte *)((longlong)puVar18 + uVar19 + 1) ^
                 (uVar27 ^ *(byte *)((longlong)puVar18 + uVar19)) * 0x100000001b3) * 0x100000001b3)
                 * 0x100000001b3) * 0x100000001b3;
        uVar19 = uVar19 + 4;
      } while ((uVar13 & 0xfffffffffffffffc) != uVar19);
      if (uVar16 == 0) goto LAB_181795604;
    }
    uVar32 = 0;
    do {
      uVar27 = (uVar27 ^ *(byte *)((longlong)puVar18 + uVar32 + uVar19)) * 0x100000001b3;
      uVar32 = uVar32 + 1;
    } while (uVar16 != uVar32);
  }
LAB_181795604:
  lVar26 = *(longlong *)(lVar36 + 0x98);
  lVar28 = (uVar27 & *(ulonglong *)(lVar36 + 0xc0)) * 0x10;
  lVar35 = *(longlong *)(*(longlong *)(lVar36 + 0xa8) + 8 + lVar28);
  if (lVar35 != lVar26) {
    lVar36 = *(longlong *)(*(longlong *)(lVar36 + 0xa8) + lVar28);
    if (uVar13 == 0) {
      for (; *(longlong *)(lVar35 + 0x20) != 0; lVar35 = *(longlong *)(lVar35 + 8)) {
        if (lVar35 == lVar36) {
          return;
        }
      }
LAB_1817956a4:
      if ((lVar35 != 0) && (lVar35 != lVar26)) {
        local_78 = 0;
        plStack_70 = (longlong *)0x0;
        plVar34 = *(longlong **)(lVar35 + 0x30);
        plVar30 = *(longlong **)(lVar35 + 0x38);
        if (plVar34 != plVar30) {
LAB_1817956e0:
          iVar11 = FUN_180f583b0(*plVar34);
          if ((iVar11 != 0) && (uVar12 = FUN_180f583b0(*plVar34), uVar12 < 4)) {
            iVar11 = FUN_180069770(2);
            if (iVar11 == 0) goto LAB_1817967cf;
            FUN_1800698a0(&local_1a8);
            ppppppuVar17 = (undefined8 ******)&local_1a8;
            if (0xf < local_190) {
              ppppppuVar17 = local_1a8;
            }
            FUN_180069c00(&local_2d8,2,ppppppuVar17,&DAT_188e6ced0,&DAT_188e73288,0x1024,0,0);
            FUN_1839bd150(*plVar34,&local_248);
            local_1f8 = (char *)&local_248;
            if (0xf < local_230) {
              local_1f8 = (char *)local_248;
            }
            uStack_1f0 = (ulonglong *******)((ulonglong)uStack_1f0 & 0xffffffffffffff00);
            uStack_b0 = 0;
            local_a8 = 0;
            uStack_c0 = 0;
            local_b8 = 0;
            uStack_d0 = 0;
            local_c8 = 0;
            uStack_e0 = 0;
            local_d8 = 0;
            uStack_f0 = 0;
            local_e8 = 0;
            puStack_100 = (undefined8 *)0x0;
            local_f8 = 0;
            puStack_110 = (undefined8 *)0x0;
            local_108 = (undefined8 *)0x0;
            uStack_a0 = 0;
            local_118 = (undefined8 *******)&local_1f8;
            FUN_18006a1a0(&local_2d8,&DAT_188e6fbc8,&local_118);
            if (0xf < local_230) {
              uVar13 = local_230 + 1;
              ppppppuVar17 = local_248;
              if (0xfff < uVar13) {
                ppppppuVar17 = (undefined8 ******)local_248[-1];
                if ((char *)0x1f < (char *)((longlong)local_248 + (-8 - (longlong)ppppppuVar17)))
                goto LAB_181796c78;
                uVar13 = local_230 + 0x28;
              }
              thunk_FUN_187306488(ppppppuVar17,uVar13);
            }
            FUN_180069d00(&local_2d8);
            ppppppuVar17 = local_1a8;
            goto joined_r0x0001817958d3;
          }
          iVar11 = FUN_180f583b0(*plVar34);
          plVar9 = plStack_70;
          if (iVar11 != 0) goto code_r0x000181795708;
          if (plVar34[1] == 0) {
            local_78 = *plVar34;
            plStack_70 = (longlong *)0x0;
            plVar34 = plStack_70;
          }
          else {
            LOCK();
            piVar2 = (int *)(plVar34[1] + 8);
            *piVar2 = *piVar2 + 1;
            UNLOCK();
            local_78 = *plVar34;
            plVar34 = (longlong *)plVar34[1];
            if (plStack_70 != (longlong *)0x0) {
              LOCK();
              plVar30 = plStack_70 + 1;
              *(int *)plVar30 = (int)*plVar30 + -1;
              UNLOCK();
              if ((int)*plVar30 == 0) {
                puVar18 = (undefined8 *)*plStack_70;
                plStack_70 = plVar34;
                (*(code *)*puVar18)(plVar9);
                LOCK();
                piVar2 = (int *)((longlong)plVar9 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                plVar34 = plStack_70;
                if (*piVar2 == 0) {
                  (**(code **)(*plVar9 + 8))(plVar9);
                  plVar34 = plStack_70;
                }
              }
            }
          }
          plStack_70 = plVar34;
          iVar11 = FUN_180069770(2);
          lVar36 = local_78;
          if (iVar11 != 0) {
            FUN_1800698a0(&local_1a8);
            ppppppuVar17 = (undefined8 ******)&local_1a8;
            if (0xf < local_190) {
              ppppppuVar17 = local_1a8;
            }
            FUN_180069c00(&local_2d8,2,ppppppuVar17,&DAT_188e6ced0,&DAT_188e73288,0x102b,0,0);
            lVar36 = local_78;
            FUN_1839bd150(local_78,&local_248);
            local_1f8 = (char *)&local_248;
            if (0xf < local_230) {
              local_1f8 = (char *)local_248;
            }
            uStack_1f0 = (ulonglong *******)((ulonglong)uStack_1f0 & 0xffffffffffffff00);
            uStack_b0 = 0;
            local_a8 = 0;
            uStack_c0 = 0;
            local_b8 = 0;
            uStack_d0 = 0;
            local_c8 = 0;
            uStack_e0 = 0;
            local_d8 = 0;
            uStack_f0 = 0;
            local_e8 = 0;
            puStack_100 = (undefined8 *)0x0;
            local_f8 = 0;
            puStack_110 = (undefined8 *)0x0;
            local_108 = (undefined8 *)0x0;
            uStack_a0 = 0;
            local_118 = (undefined8 *******)&local_1f8;
            FUN_18006a1a0(&local_2d8,&DAT_188e77af0,&local_118);
            if (0xf < local_230) {
              uVar13 = local_230 + 1;
              ppppppuVar17 = local_248;
              if (0xfff < uVar13) {
                ppppppuVar17 = (undefined8 ******)local_248[-1];
                if ((char *)0x1f < (char *)((longlong)local_248 + (-8 - (longlong)ppppppuVar17)))
                goto LAB_181796c78;
                uVar13 = local_230 + 0x28;
              }
              thunk_FUN_187306488(ppppppuVar17,uVar13);
            }
            FUN_180069d00(&local_2d8);
            if (0xf < local_190) {
              uVar13 = local_190 + 1;
              ppppppuVar17 = local_1a8;
              if (0xfff < uVar13) {
                ppppppuVar17 = (undefined8 ******)local_1a8[-1];
                if ((char *)0x1f < (char *)((longlong)local_1a8 + (-8 - (longlong)ppppppuVar17)))
                goto LAB_181796c78;
                uVar13 = local_190 + 0x28;
              }
              thunk_FUN_187306488(ppppppuVar17,uVar13);
            }
          }
          pppppppuVar25 = _UNK_188ad27c8;
          ppppppuVar17 = _DAT_188ad27c0;
          if (lVar36 != 0) {
            if (*(longlong *)(lVar36 + 0x20) == 0) {
              plStack_80 = (longlong *)0x0;
            }
            else {
              LOCK();
              piVar2 = (int *)(*(longlong *)(lVar36 + 0x20) + 8);
              *piVar2 = *piVar2 + 1;
              UNLOCK();
              plStack_80 = *(longlong **)(lVar36 + 0x20);
            }
            local_88 = *(longlong *)(lVar36 + 0x18);
            iVar11 = FUN_180069770(2);
            if (iVar11 != 0) {
              FUN_1800698a0(&local_430);
              pppppppuVar24 = &local_430;
              if (0xf < local_418) {
                pppppppuVar24 = local_430;
              }
              FUN_180069c00(&local_2d8,2,pppppppuVar24,&DAT_188e6ced0,&DAT_188e73288,0x1037,0,0);
              lVar36 = local_88;
              if (local_88 == 0) {
                uVar12 = 0;
              }
              else {
                uVar12 = *(uint *)(local_88 + 0x10);
              }
              local_1f8 = (char *)0x0;
              uVar13 = 7;
              puVar31 = (undefined1 *)((longlong)&local_1f8 + 7);
              do {
                puVar23 = puVar31;
                puVar23[1] = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             [uVar12 % 10 + 0x23];
                puVar31 = puVar23 + 1;
                uVar13 = uVar13 + 1;
                bVar37 = 9 < uVar12;
                uVar12 = uVar12 / 10;
              } while (bVar37);
              puVar23[2] = 0;
              if (8 < uVar13) {
                puVar23 = (undefined1 *)((longlong)&uStack_1f0 + 1);
                do {
                  uVar4 = *puVar31;
                  *puVar31 = puVar23[-1];
                  puVar31 = puVar31 + -1;
                  puVar23[-1] = uVar4;
                  bVar37 = puVar23 < puVar31;
                  puVar23 = puVar23 + 1;
                } while (bVar37);
              }
              local_1f8 = (char *)&uStack_1f0;
              if (lVar36 == 0) {
                uVar12 = 0;
              }
              else {
                uVar12 = *(uint *)(lVar36 + 0xc);
              }
              local_1a8 = (undefined8 ******)0x0;
              uVar13 = 7;
              puVar31 = (undefined1 *)((longlong)&local_1a8 + 7);
              do {
                puVar23 = puVar31;
                puVar23[1] = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             [uVar12 % 10 + 0x23];
                puVar31 = puVar23 + 1;
                uVar13 = uVar13 + 1;
                bVar37 = 9 < uVar12;
                uVar12 = uVar12 / 10;
              } while (bVar37);
              local_1a8 = (undefined8 ******)&local_1a0;
              puVar23[2] = 0;
              if (8 < uVar13) {
                puVar23 = (undefined1 *)((longlong)&local_1a0 + 1);
                do {
                  uVar4 = *puVar31;
                  *puVar31 = puVar23[-1];
                  puVar31 = puVar31 + -1;
                  puVar23[-1] = uVar4;
                  bVar37 = puVar23 < puVar31;
                  puVar23 = puVar23 + 1;
                } while (bVar37);
              }
              FUN_1839bd150(local_78,&local_158);
              local_248 = (undefined8 ******)&local_158;
              if (&DAT_0000000f < pppppppuStack_140) {
                local_248 = local_158;
              }
              local_240._0_1_ = 0;
              uStack_b0 = 0;
              local_a8 = 0;
              uStack_c0 = 0;
              local_b8 = 0;
              uStack_d0 = 0;
              local_c8 = 0;
              uStack_e0 = 0;
              local_d8 = 0;
              uStack_f0 = 0;
              local_e8 = 0;
              puStack_100 = (undefined8 *)0x0;
              local_f8 = 0;
              uStack_a0 = 0;
              local_118 = (undefined8 *******)&local_248;
              puStack_110 = &local_1a8;
              local_108 = &local_1f8;
              FUN_18006a1a0(&local_2d8,&DAT_188e71ff0,&local_118);
              if (&DAT_0000000f < pppppppuStack_140) {
                pppppppuVar29 = (ulonglong *******)((longlong)pppppppuStack_140 + 1);
                ppppppuVar22 = local_158;
                if (pppppppuVar29 < (ulonglong *******)0x1000) {
LAB_181795ec5:
                  thunk_FUN_187306488(ppppppuVar22,pppppppuVar29);
                  goto LAB_181795eca;
                }
                ppppppuVar22 = (undefined8 ******)local_158[-1];
                if ((char *)((longlong)local_158 + (-8 - (longlong)ppppppuVar22)) < (char *)0x20) {
                  pppppppuVar29 = pppppppuStack_140 + 5;
                  goto LAB_181795ec5;
                }
                goto LAB_181796c78;
              }
LAB_181795eca:
              FUN_180069d00(&local_2d8);
              if (0xf < local_418) {
                uVar13 = local_418 + 1;
                pppppppuVar24 = local_430;
                if (0xfff < uVar13) {
                  pppppppuVar24 = (undefined8 *******)local_430[-1];
                  if (0x1f < (ulonglong)((longlong)local_430 + (-8 - (longlong)pppppppuVar24)))
                  goto LAB_181796c78;
                  uVar13 = local_418 + 0x28;
                }
                thunk_FUN_187306488(pppppppuVar24,uVar13);
              }
            }
            lVar36 = local_78;
            local_128 = (longlong *)&DAT_aaaaaaaaaaaaaaaa;
            local_138 = ppppppuVar17;
            pppppppuStack_130 = pppppppuVar25;
            local_148 = ppppppuVar17;
            pppppppuStack_140 = pppppppuVar25;
            local_158 = ppppppuVar17;
            pppppppuStack_150 = pppppppuVar25;
            if (plStack_70 == (longlong *)0x0) {
              plStack_310 = (longlong *)0x0;
            }
            else {
              LOCK();
              *(int *)(plStack_70 + 1) = (int)plStack_70[1] + 1;
              UNLOCK();
              plStack_310 = plStack_70;
            }
            local_318 = local_78;
            FUN_1817f4fc0(param_1,&local_158,&local_318);
            plVar34 = plStack_80;
            if (*(longlong *)(lVar36 + 0x20) == 0) {
              local_88 = *(longlong *)(lVar36 + 0x18);
LAB_181795fb3:
              bVar37 = true;
              plVar30 = (longlong *)0x0;
            }
            else {
              LOCK();
              piVar2 = (int *)(*(longlong *)(lVar36 + 0x20) + 8);
              *piVar2 = *piVar2 + 1;
              UNLOCK();
              local_88 = *(longlong *)(lVar36 + 0x18);
              plVar30 = *(longlong **)(lVar36 + 0x20);
              if (plVar30 == (longlong *)0x0) goto LAB_181795fb3;
              LOCK();
              *(int *)(plVar30 + 1) = (int)plVar30[1] + 1;
              UNLOCK();
              bVar37 = false;
            }
            plVar9 = plVar30;
            if (plStack_80 != (longlong *)0x0) {
              LOCK();
              plVar1 = plStack_80 + 1;
              *(int *)plVar1 = (int)*plVar1 + -1;
              UNLOCK();
              if ((int)*plVar1 == 0) {
                puVar18 = (undefined8 *)*plStack_80;
                plStack_80 = plVar30;
                (*(code *)*puVar18)(plVar34);
                LOCK();
                piVar2 = (int *)((longlong)plVar34 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                plVar9 = plStack_80;
                if (*piVar2 == 0) {
                  (**(code **)(*plVar34 + 8))(plVar34);
                  plVar9 = plStack_80;
                }
              }
            }
            plStack_80 = plVar9;
            if (!bVar37) {
              LOCK();
              plVar34 = plVar30 + 1;
              *(int *)plVar34 = (int)*plVar34 + -1;
              UNLOCK();
              if ((int)*plVar34 == 0) {
                (**(code **)*plVar30)(plVar30);
                LOCK();
                piVar2 = (int *)((longlong)plVar30 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (**(code **)(*plVar30 + 8))(plVar30);
                }
              }
            }
            iVar11 = FUN_180069770(2);
            lVar36 = local_78;
            if (iVar11 != 0) {
              FUN_1800698a0(local_3a0);
              pppppppuVar24 = local_3a0;
              if (0xf < local_388) {
                pppppppuVar24 = local_3a0[0];
              }
              FUN_180069c00(&local_2d8,2,pppppppuVar24,&DAT_188e6ced0,&DAT_188e73288,0x103b,0,0);
              lVar36 = local_88;
              local_1f8 = (char *)&DAT_188b0d2ac;
              if (local_158._4_4_ == 0 && (int)local_158 == 0) {
                local_1f8 = "false";
              }
              uStack_1f0 = (ulonglong *******)((ulonglong)uStack_1f0 & 0xffffffffffffff00);
              if (local_88 == 0) {
                uVar12 = 0;
              }
              else {
                uVar12 = *(uint *)(local_88 + 0x10);
              }
              local_1a8 = (undefined8 ******)0x0;
              uVar13 = 7;
              puVar31 = (undefined1 *)((longlong)&local_1a8 + 7);
              do {
                puVar23 = puVar31;
                puVar23[1] = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             [uVar12 % 10 + 0x23];
                puVar31 = puVar23 + 1;
                uVar13 = uVar13 + 1;
                bVar37 = 9 < uVar12;
                uVar12 = uVar12 / 10;
              } while (bVar37);
              puVar23[2] = 0;
              if (8 < uVar13) {
                puVar23 = (undefined1 *)((longlong)&local_1a0 + 1);
                do {
                  uVar4 = *puVar31;
                  *puVar31 = puVar23[-1];
                  puVar31 = puVar31 + -1;
                  puVar23[-1] = uVar4;
                  bVar37 = puVar23 < puVar31;
                  puVar23 = puVar23 + 1;
                } while (bVar37);
              }
              local_1a8 = (undefined8 ******)&local_1a0;
              if (lVar36 == 0) {
                uVar12 = 0;
              }
              else {
                uVar12 = *(uint *)(lVar36 + 0xc);
              }
              local_248 = (undefined8 ******)0x0;
              uVar13 = 7;
              puVar31 = (undefined1 *)((longlong)&local_248 + 7);
              do {
                puVar23 = puVar31;
                puVar23[1] = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             [uVar12 % 10 + 0x23];
                puVar31 = puVar23 + 1;
                uVar13 = uVar13 + 1;
                bVar37 = 9 < uVar12;
                uVar12 = uVar12 / 10;
              } while (bVar37);
              local_248 = (undefined8 ******)&local_240;
              puVar23[2] = 0;
              if (8 < uVar13) {
                puVar23 = (undefined1 *)((longlong)&local_240 + 1);
                do {
                  uVar4 = *puVar31;
                  *puVar31 = puVar23[-1];
                  puVar31 = puVar31 + -1;
                  puVar23[-1] = uVar4;
                  bVar37 = puVar23 < puVar31;
                  puVar23 = puVar23 + 1;
                } while (bVar37);
              }
              lVar36 = local_78;
              FUN_1839bd150(local_78,local_380);
              local_430 = local_380;
              if (0xf < local_368) {
                local_430 = local_380[0];
              }
              local_428 = 0;
              local_a8 = 0;
              uStack_a0 = 0;
              local_b8 = 0;
              uStack_b0 = 0;
              local_c8 = 0;
              uStack_c0 = 0;
              local_d8 = 0;
              uStack_d0 = 0;
              local_e8 = 0;
              uStack_e0 = 0;
              local_f8 = 0;
              uStack_f0 = 0;
              local_118 = &local_430;
              puStack_110 = &local_248;
              local_108 = &local_1a8;
              puStack_100 = &local_1f8;
              FUN_18006a1a0(&local_2d8,&DAT_188e70cf0,&local_118);
              if (0xf < local_368) {
                uVar13 = local_368 + 1;
                pppppppuVar24 = local_380[0];
                if (0xfff < uVar13) {
                  pppppppuVar24 = (undefined8 *******)local_380[0][-1];
                  if (0x1f < (ulonglong)((longlong)local_380[0] + (-8 - (longlong)pppppppuVar24)))
                  goto LAB_181796c78;
                  uVar13 = local_368 + 0x28;
                }
                thunk_FUN_187306488(pppppppuVar24,uVar13);
              }
              FUN_180069d00(&local_2d8);
              if (0xf < local_388) {
                uVar13 = local_388 + 1;
                pppppppuVar24 = local_3a0[0];
                if (0xfff < uVar13) {
                  pppppppuVar24 = (undefined8 *******)local_3a0[0][-1];
                  if (0x1f < (ulonglong)((longlong)local_3a0[0] + (-8 - (longlong)pppppppuVar24)))
                  goto LAB_181796c78;
                  uVar13 = local_388 + 0x28;
                }
                thunk_FUN_187306488(pppppppuVar24,uVar13);
              }
            }
            lVar26 = lVar36 + 0x38;
            if (plStack_70 == (longlong *)0x0) {
              plStack_300 = (longlong *)0x0;
            }
            else {
              LOCK();
              *(int *)(plStack_70 + 1) = (int)plStack_70[1] + 1;
              UNLOCK();
              plStack_300 = plStack_70;
              lVar36 = local_78;
            }
            local_308 = lVar36;
            FUN_1817f1010(0,*(longlong *)(param_1 + 0xbf8) + 0x90,&local_308,lVar26);
            if ((local_158._4_4_ != 0 || (int)local_158 != 0) ||
               (cVar10 = FUN_181e2f4a0(lVar36), lVar36 = local_78, cVar10 == '\0')) {
              iVar11 = FUN_180069770(4);
              if (iVar11 != 0) {
                FUN_1800698a0(&local_1a8);
                ppppppuVar17 = (undefined8 ******)&local_1a8;
                if (0xf < local_190) {
                  ppppppuVar17 = local_1a8;
                }
                FUN_180069c00(&local_2d8,4,ppppppuVar17,&DAT_188e6ced0,&DAT_188e73288,0x103e,0,0);
                FUN_1839bd150(local_78,&local_248);
                local_1f8 = (char *)&local_248;
                if (0xf < local_230) {
                  local_1f8 = (char *)local_248;
                }
                uStack_1f0 = (ulonglong *******)((ulonglong)uStack_1f0 & 0xffffffffffffff00);
                uStack_b0 = 0;
                local_a8 = 0;
                uStack_c0 = 0;
                local_b8 = 0;
                uStack_d0 = 0;
                local_c8 = 0;
                uStack_e0 = 0;
                local_d8 = 0;
                uStack_f0 = 0;
                local_e8 = 0;
                puStack_100 = (undefined8 *)0x0;
                local_f8 = 0;
                puStack_110 = (undefined8 *)0x0;
                local_108 = (undefined8 *)0x0;
                uStack_a0 = 0;
                local_118 = (undefined8 *******)&local_1f8;
                FUN_18006a1a0(&local_2d8,&DAT_188e77ba0,&local_118);
                if (0xf < local_230) {
                  uVar13 = local_230 + 1;
                  ppppppuVar17 = local_248;
                  if (0xfff < uVar13) {
                    ppppppuVar17 = (undefined8 ******)local_248[-1];
                    if ((char *)0x1f < (char *)((longlong)local_248 + (-8 - (longlong)ppppppuVar17))
                       ) goto LAB_181796c78;
                    uVar13 = local_230 + 0x28;
                  }
                  thunk_FUN_187306488(ppppppuVar17,uVar13);
                }
                FUN_180069d00(&local_2d8);
                if (0xf < local_190) {
                  uVar13 = local_190 + 1;
                  ppppppuVar17 = local_1a8;
                  if (0xfff < uVar13) {
                    ppppppuVar17 = (undefined8 ******)local_1a8[-1];
                    if ((char *)0x1f < (char *)((longlong)local_1a8 + (-8 - (longlong)ppppppuVar17))
                       ) goto LAB_181796c78;
                    uVar13 = local_190 + 0x28;
                  }
                  thunk_FUN_187306488(ppppppuVar17,uVar13);
                }
              }
              pppppppuVar25 = pppppppuStack_140;
              local_360 = local_158;
              local_358 = (ulonglong ******)0x0;
              ppppppuStack_350 = (ulonglong ******)0x0;
              local_348 = (ulonglong *******)0x0;
              uStack_340 = 0;
              pppppppuVar29 = pppppppuStack_150;
              if (local_138 < &DAT_00000010) {
                pppppppuVar29 = (ulonglong *******)&pppppppuStack_150;
              }
              if (-1 < (longlong)pppppppuStack_140) {
                if (&DAT_0000000f < pppppppuStack_140) {
                  uVar27 = (ulonglong)pppppppuStack_140 | 0xf;
                  uVar13 = 0x16;
                  if (0x16 < uVar27) {
                    uVar13 = uVar27;
                  }
                  if (uVar27 < 0xfff) {
                    local_358 = (ulonglong ******)operator_new(uVar13 + 1);
                  }
                  else {
                    pppppuVar14 = (ulonglong *****)operator_new(uVar13 + 0x28);
                    if (pppppuVar14 == (ulonglong *****)0x0) goto LAB_181796c78;
                    local_358 = (ulonglong ******)
                                ((longlong)pppppuVar14 + 0x27U & 0xffffffffffffffe0);
                    local_358[-1] = pppppuVar14;
                  }
                  local_348 = pppppppuVar25;
                  uStack_340 = uVar13;
                  FUN_18732e860(local_358,pppppppuVar29,(undefined1 *)((longlong)pppppppuVar25 + 1))
                  ;
                }
                else {
                  local_348 = pppppppuStack_140;
                  uStack_340 = 0xf;
                  local_358 = *pppppppuVar29;
                  ppppppuStack_350 = pppppppuVar29[1];
                }
                if (local_128 == (longlong *)0x0) {
                  plStack_330 = (longlong *)0x0;
                }
                else {
                  LOCK();
                  *(int *)(local_128 + 1) = (int)local_128[1] + 1;
                  UNLOCK();
                  plStack_330 = local_128;
                }
                local_338 = pppppppuStack_130;
                if (plStack_70 == (longlong *)0x0) {
                  plStack_2f0 = (longlong *)0x0;
                }
                else {
                  LOCK();
                  *(int *)(plStack_70 + 1) = (int)plStack_70[1] + 1;
                  UNLOCK();
                  plStack_2f0 = plStack_70;
                }
                local_2f8 = local_78;
                FUN_182435ce0(&local_2f8,&local_360);
                FUN_181795500(param_1,param_2);
                goto LAB_181796738;
              }
              goto LAB_181796c7e;
            }
            FUN_1839be5b0(local_78,4);
            FUN_1839be590(lVar36,&local_2d8);
            if (plStack_70 == (longlong *)0x0) {
              plVar34 = (longlong *)0x0;
            }
            else {
              LOCK();
              *(int *)(plStack_70 + 1) = (int)plStack_70[1] + 1;
              UNLOCK();
              lVar36 = local_78;
              plVar34 = plStack_70;
            }
            local_2e8 = lVar36;
            plStack_2e0 = plVar34;
            FUN_1817948c0(0,*(longlong *)(param_1 + 0xbf8) + 0xd0,&local_2e8,&local_2d8);
            if (&DAT_0000000f < local_2c0) {
              pppppppuVar24 = (undefined8 *******)((longlong)local_2c0 + 1);
              lVar26 = local_2d8;
              if ((undefined8 *******)0xfff < pppppppuVar24) {
                lVar26 = *(longlong *)(local_2d8 + -8);
                if (0x1f < (ulonglong)((local_2d8 + -8) - lVar26)) goto LAB_181796c78;
                pppppppuVar24 = local_2c0 + 5;
              }
              thunk_FUN_187306488(lVar26,pppppppuVar24);
            }
            local_1f8 = (char *)ppppppuVar17;
            uStack_1f0 = pppppppuVar25;
            uVar15 = FUN_1800425a0();
            FUN_180043ba0(uVar15,&local_1a8);
            if (plVar34 == (longlong *)0x0) {
              local_3d0 = (longlong *)0x0;
            }
            else {
              LOCK();
              *(int *)(plVar34 + 1) = (int)plVar34[1] + 1;
              UNLOCK();
              local_3d0 = plStack_70;
              lVar36 = local_78;
            }
            local_3e0 = &PTR_LAB_188e6b008;
            local_3a8 = &local_3e0;
            if (local_3d0 == (longlong *)0x0) {
              plVar34 = (longlong *)0x0;
              lVar26 = lVar36;
            }
            else {
              LOCK();
              *(int *)(local_3d0 + 1) = (int)local_3d0[1] + 1;
              UNLOCK();
              lVar26 = local_78;
              plVar34 = plStack_70;
            }
            local_2c0 = (undefined8 *******)0x0;
            uStack_2b8 = 0;
            local_2b0 = 0;
            uStack_2a8 = 0;
            uVar13 = param_2[2];
            if (0xf < (ulonglong)param_2[3]) {
              param_2 = (undefined8 *)*param_2;
            }
            local_3d8 = lVar36;
            local_3c8 = param_1;
            local_2d8 = lVar26;
            plStack_2d0 = plVar34;
            local_2c8 = param_1;
            if ((longlong)uVar13 < 0) goto LAB_181796c84;
            local_328 = local_1a8;
            if (uVar13 < 0x10) {
              uStack_2a8 = 0xf;
              local_2c0 = (undefined8 *******)*param_2;
              uStack_2b8 = param_2[1];
              uVar27 = 0xf;
              local_2b0 = uVar13;
            }
            else {
              uVar16 = uVar13 | 0xf;
              uVar27 = 0x16;
              if (0x16 < uVar16) {
                uVar27 = uVar16;
              }
              if (uVar16 < 0xfff) {
                local_2c0 = (undefined8 *******)operator_new(uVar27 + 1);
              }
              else {
                ppppppuVar17 = (undefined8 ******)operator_new(uVar27 + 0x28);
                if (ppppppuVar17 == (undefined8 ******)0x0) goto LAB_181796c78;
                local_2c0 = (undefined8 *******)
                            ((longlong)ppppppuVar17 + 0x27U & 0xffffffffffffffe0);
                local_2c0[-1] = ppppppuVar17;
              }
              local_2b0 = uVar13;
              uStack_2a8 = uVar27;
              FUN_18732e860(local_2c0,param_2,uVar13 + 1);
            }
            local_438 = (undefined8 *)0x0;
            puVar18 = (undefined8 *)operator_new(0x40);
            pppppppuVar24 = local_2c0;
            *puVar18 = &PTR_LAB_188e6af68;
            puVar18[1] = lVar26;
            puVar18[2] = plVar34;
            local_2d8 = 0;
            plStack_2d0 = (longlong *)0x0;
            puVar18[3] = param_1;
            puVar18[4] = 0;
            puVar18[5] = 0;
            puVar18[6] = 0;
            puVar18[7] = 0;
            pppppppuVar33 = &local_2c0;
            if (0xf < uVar27) {
              pppppppuVar33 = local_2c0;
            }
            if (uVar13 < 0x10) {
              puVar18[6] = uVar13;
              puVar18[7] = 0xf;
              uVar6 = *(undefined4 *)((longlong)pppppppuVar33 + 4);
              uVar7 = *(undefined4 *)(pppppppuVar33 + 1);
              uVar8 = *(undefined4 *)((longlong)pppppppuVar33 + 0xc);
              *(undefined4 *)(puVar18 + 4) = *(undefined4 *)pppppppuVar33;
              *(undefined4 *)((longlong)puVar18 + 0x24) = uVar6;
              *(undefined4 *)(puVar18 + 5) = uVar7;
              *(undefined4 *)((longlong)puVar18 + 0x2c) = uVar8;
            }
            else {
              local_320 = puVar18 + 1;
              uVar19 = uVar13 | 0xf;
              uVar16 = 0x16;
              if (0x16 < uVar19) {
                uVar16 = uVar19;
              }
              local_90 = puVar18;
              if (uVar19 < 0xfff) {
                pvVar21 = operator_new(uVar16 + 1);
              }
              else {
                pvVar20 = operator_new(uVar16 + 0x28);
                if (pvVar20 == (void *)0x0) goto LAB_181796c78;
                pvVar21 = (void *)((longlong)pvVar20 + 0x27U & 0xffffffffffffffe0);
                *(void **)((longlong)pvVar21 - 8) = pvVar20;
              }
              puVar18 = local_90;
              local_90[4] = pvVar21;
              local_90[6] = uVar13;
              local_90[7] = uVar16;
              FUN_18732e860(pvVar21,pppppppuVar33,uVar13 + 1);
            }
            local_61 = 1;
            local_438 = puVar18;
            FUN_180199830(&local_118,&DAT_188e77c10,&DAT_188e6ced0,0x1048);
            local_61 = 0;
            FUN_1802d1430(local_328,&local_1f8,&local_118,local_470,&local_3e0,0);
            if (0xf < uVar27) {
              if (uVar27 < 0xfff) {
                lVar36 = uVar27 + 1;
              }
              else {
                if ((undefined1 *)0x1f <
                    (undefined1 *)((longlong)pppppppuVar24 + (-8 - (longlong)pppppppuVar24[-1])))
                goto LAB_181796c78;
                lVar36 = uVar27 + 0x28;
                pppppppuVar24 = (undefined8 *******)pppppppuVar24[-1];
              }
              thunk_FUN_187306488(pppppppuVar24,lVar36);
            }
            if (local_1a0 != (undefined8 *****)0x0) {
              LOCK();
              pppppuVar3 = local_1a0 + 1;
              *(int *)pppppuVar3 = *(int *)pppppuVar3 + -1;
              UNLOCK();
              if (*(int *)pppppuVar3 == 0) {
                (*(code *)**local_1a0)(local_1a0);
                LOCK();
                piVar2 = (int *)((longlong)local_1a0 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (*(code *)(*local_1a0)[1])(local_1a0);
                }
              }
            }
            if (uStack_1f0 == (ulonglong *******)0x0) {
LAB_181796bed:
              bVar37 = true;
              pppppppuVar25 = (ulonglong *******)0x0;
            }
            else {
              LOCK();
              *(int *)(uStack_1f0 + 1) = *(int *)(uStack_1f0 + 1) + 1;
              UNLOCK();
              if (uStack_1f0 == (ulonglong *******)0x0) goto LAB_181796bed;
              LOCK();
              *(int *)(uStack_1f0 + 1) = *(int *)(uStack_1f0 + 1) + 1;
              UNLOCK();
              bVar37 = false;
              pppppppuVar25 = uStack_1f0;
            }
            *(char **)(local_78 + 0x58) = local_1f8;
            plVar34 = *(longlong **)(local_78 + 0x60);
            *(ulonglong ********)(local_78 + 0x60) = pppppppuVar25;
            if (plVar34 != (longlong *)0x0) {
              LOCK();
              plVar30 = plVar34 + 1;
              *(int *)plVar30 = (int)*plVar30 + -1;
              UNLOCK();
              if ((int)*plVar30 == 0) {
                (**(code **)*plVar34)(plVar34);
                LOCK();
                piVar2 = (int *)((longlong)plVar34 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (**(code **)(*plVar34 + 8))(plVar34);
                }
              }
            }
            if (!bVar37) {
              LOCK();
              pppppppuVar29 = pppppppuVar25 + 1;
              *(int *)pppppppuVar29 = *(int *)pppppppuVar29 + -1;
              UNLOCK();
              if (*(int *)pppppppuVar29 == 0) {
                (*(code *)**pppppppuVar25)(pppppppuVar25);
                LOCK();
                piVar2 = (int *)((longlong)pppppppuVar25 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (*(code *)(*pppppppuVar25)[1])(pppppppuVar25);
                }
              }
            }
            pppppppuVar25 = uStack_1f0;
            if (uStack_1f0 != (ulonglong *******)0x0) {
              LOCK();
              pppppppuVar29 = uStack_1f0 + 1;
              *(int *)pppppppuVar29 = *(int *)pppppppuVar29 + -1;
              UNLOCK();
              if (*(int *)pppppppuVar29 == 0) {
                (*(code *)**uStack_1f0)(uStack_1f0);
                LOCK();
                piVar2 = (int *)((longlong)pppppppuVar25 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (*(code *)(*pppppppuVar25)[1])(pppppppuVar25);
                }
              }
            }
LAB_181796738:
            plVar34 = local_128;
            if (local_128 != (longlong *)0x0) {
              LOCK();
              plVar30 = local_128 + 1;
              *(int *)plVar30 = (int)*plVar30 + -1;
              UNLOCK();
              if ((int)*plVar30 == 0) {
                (**(code **)*local_128)(local_128);
                LOCK();
                piVar2 = (int *)((longlong)plVar34 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (**(code **)(*plVar34 + 8))(plVar34);
                }
              }
            }
            if (&DAT_0000000f < local_138) {
              ppppppuVar17 = (undefined8 ******)((longlong)local_138 + 1);
              pppppppuVar25 = pppppppuStack_150;
              if ((undefined8 ******)0xfff < ppppppuVar17) {
                pppppppuVar25 = (ulonglong *******)pppppppuStack_150[-1];
                if ((undefined1 *)0x1f <
                    (undefined1 *)((longlong)pppppppuStack_150 + (-8 - (longlong)pppppppuVar25)))
                goto LAB_181796c78;
                ppppppuVar17 = local_138 + 5;
              }
              thunk_FUN_187306488(pppppppuVar25,ppppppuVar17);
            }
            plVar34 = plStack_80;
            if (plStack_80 != (longlong *)0x0) {
              LOCK();
              plVar30 = plStack_80 + 1;
              *(int *)plVar30 = (int)*plVar30 + -1;
              UNLOCK();
              if ((int)*plVar30 == 0) {
                (**(code **)*plStack_80)(plStack_80);
                LOCK();
                piVar2 = (int *)((longlong)plVar34 + 0xc);
                *piVar2 = *piVar2 + -1;
                UNLOCK();
                if (*piVar2 == 0) {
                  (**(code **)(*plVar34 + 8))(plVar34);
                }
              }
            }
            goto LAB_1817967cf;
          }
        }
LAB_181795ae9:
        iVar11 = FUN_180069770(2);
        if (iVar11 != 0) {
          FUN_1800698a0(&local_1f8);
          ppppppuVar17 = (undefined8 ******)&local_1f8;
          if (0xf < local_1e0) {
            ppppppuVar17 = (undefined8 ******)local_1f8;
          }
          FUN_180069c00(&local_2d8,2,ppppppuVar17,&DAT_188e6ced0,&DAT_188e73288,0x1031,0,0);
          local_a8 = 0;
          uStack_a0 = 0;
          local_b8 = 0;
          uStack_b0 = 0;
          local_c8 = 0;
          uStack_c0 = 0;
          local_d8 = 0;
          uStack_d0 = 0;
          local_e8 = 0;
          uStack_e0 = 0;
          local_f8 = 0;
          uStack_f0 = 0;
          local_108 = (undefined8 *)0x0;
          puStack_100 = (undefined8 *)0x0;
          local_118 = (undefined8 *******)0x0;
          puStack_110 = (undefined8 *)0x0;
          FUN_18006a1a0(&local_2d8,&DAT_188e6cc40,&local_118);
          FUN_180069d00(&local_2d8);
          ppppppuVar17 = (undefined8 ******)local_1f8;
          local_190 = local_1e0;
joined_r0x0001817958d3:
          if (0xf < local_190) {
            uVar13 = local_190 + 1;
            ppppppuVar22 = ppppppuVar17;
            if (0xfff < uVar13) {
              ppppppuVar22 = *(undefined8 *******)((longlong)ppppppuVar17 + 0xfffffffffffffff8);
              if ((char *)0x1f < (char *)((longlong)ppppppuVar17 + (-8 - (longlong)ppppppuVar22))) {
LAB_181796c78:
                FUN_1872f7bac();
LAB_181796c7e:
                FUN_180008c20();
LAB_181796c84:
                FUN_180008c20();
                pcVar5 = (code *)swi(3);
                (*pcVar5)();
                return;
              }
              uVar13 = local_190 + 0x28;
            }
            thunk_FUN_187306488(ppppppuVar22,uVar13);
          }
        }
LAB_1817967cf:
        plVar34 = plStack_70;
        if (plStack_70 != (longlong *)0x0) {
          LOCK();
          plVar30 = plStack_70 + 1;
          *(int *)plVar30 = (int)*plVar30 + -1;
          UNLOCK();
          if ((int)*plVar30 == 0) {
            (**(code **)*plStack_70)(plStack_70);
            LOCK();
            piVar2 = (int *)((longlong)plVar34 + 0xc);
            *piVar2 = *piVar2 + -1;
            UNLOCK();
            if (*piVar2 == 0) {
              (**(code **)(*plVar34 + 8))(plVar34);
            }
          }
        }
      }
    }
    else {
      uVar27 = *(ulonglong *)(lVar35 + 0x20);
      while( true ) {
        if (uVar13 == uVar27) {
          if (*(ulonglong *)(lVar35 + 0x28) < 0x10) {
            pvVar21 = (void *)(lVar35 + 0x10);
          }
          else {
            pvVar21 = *(void **)(lVar35 + 0x10);
          }
          iVar11 = memcmp(puVar18,pvVar21,uVar13);
          if (iVar11 == 0) goto LAB_1817956a4;
        }
        if (lVar35 == lVar36) break;
        lVar35 = *(longlong *)(lVar35 + 8);
        uVar27 = *(ulonglong *)(lVar35 + 0x20);
      }
    }
  }
  return;
code_r0x000181795708:
  plVar34 = plVar34 + 2;
  if (plVar34 == plVar30) goto LAB_181795ae9;
  goto LAB_1817956e0;
}

