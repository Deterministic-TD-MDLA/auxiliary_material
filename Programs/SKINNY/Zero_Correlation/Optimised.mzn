int: R1;
int: R2;
array[0..3, 0..3] of 0..3: InputPattern;
array[0..3, 0..3] of 0..3: OutputPattern;
% ------------- Forward ---------------- %
array[0..R1, 0..3, 0..3] of var 0..3: ForwardMaskX;
array[0..R1, 0..3, 0..3] of var -2..15: ForwardClassX;
constraint forall(i in 0..R1, j in 0..3, k in 0..3)( LinkMaskClass(ForwardMaskX[i,j,k], ForwardClassX[i,j,k]) );

array[0..R1-1, 0..3, 0..3] of var 0..3: ForwardMaskSBX;
array[0..R1-1, 0..3, 0..3] of var -2..15: ForwardClassSBX;
constraint forall(i in 0..R1-1, j in 0..3, k in 0..3)( LinkMaskClass(ForwardMaskSBX[i,j,k], ForwardClassSBX[i,j,k]) );

array[0..R1-1, 0..3] of var 0..3: ForwardMaskAux;
array[0..R1-1, 0..3] of var -2..15: ForwardClassAux;
constraint forall(i in 0..R1-1, j in 0..3)( LinkMaskClass(ForwardMaskAux[i,j], ForwardClassAux[i,j]) );
% Fix Input Mask
constraint forall(i in 0..3, j in 0..3)
(
    ForwardMaskX[0,i,j] = InputPattern[i,j]
);
% SB Operation
constraint forall(r in 0..0, i in 0..3, j in 0..3)
(
    ForwardMaskSBX[r,i,j] = ForwardMaskX[r,i,j] /\
    ForwardClassSBX[r,i,j] = ForwardClassX[r,i,j]
);
constraint forall(r in 1..R1-1, i in 0..3, j in 0..3)
(
    SBOperation(ForwardMaskX[r,i,j], ForwardMaskSBX[r,i,j])
);
% MixColumn
constraint forall(r in 0..R1-1, j in 0..3)
(
    MixColumnForward(ForwardMaskSBX[r,0,(j-0+4) mod 4], ForwardClassSBX[r,0,(j-0+4) mod 4],
                     ForwardMaskSBX[r,1,(j-1+4) mod 4], ForwardClassSBX[r,1,(j-1+4) mod 4],
                     ForwardMaskSBX[r,2,(j-2+4) mod 4], ForwardClassSBX[r,2,(j-2+4) mod 4],
                     ForwardMaskSBX[r,3,(j-3+4) mod 4], ForwardClassSBX[r,3,(j-3+4) mod 4],
                     ForwardMaskX[r+1,0,j], ForwardClassX[r+1,0,j], 
                     ForwardMaskX[r+1,1,j], ForwardClassX[r+1,1,j],
                     ForwardMaskX[r+1,2,j], ForwardClassX[r+1,2,j],
                     ForwardMaskX[r+1,3,j], ForwardClassX[r+1,3,j],
                     ForwardMaskAux[r,j], ForwardClassAux[r,j])
                     
);
% ------------------------------------------------------------- %
% ------------- Backward ---------------- %
array[0..R2, 0..3, 0..3] of var 0..3: BackwardMaskX;
array[0..R2, 0..3, 0..3] of var -2..15: BackwardClassX;
constraint forall(i in 0..R2, j in 0..3, k in 0..3)( LinkMaskClass(BackwardMaskX[i,j,k], BackwardClassX[i,j,k]) );

array[0..R2-1, 0..3, 0..3] of var 0..3: BackwardMaskSBX;
array[0..R2-1, 0..3, 0..3] of var -2..15: BackwardClassSBX;
constraint forall(i in 0..R2-1, j in 0..3, k in 0..3)( LinkMaskClass(BackwardMaskSBX[i,j,k], BackwardClassSBX[i,j,k]) );

array[0..R2-1, 0..3] of var 0..3: BackwardMaskAux;
array[0..R2-1, 0..3] of var -2..15: BackwardClassAux;
constraint forall(i in 0..R2-1, j in 0..3)( LinkMaskClass(BackwardMaskAux[i,j], BackwardClassAux[i,j]) );
% ----------------------------- %
% Fix Output Mask
constraint forall(i in 0..3, j in 0..3)
(
    BackwardMaskX[R2,i,j] = OutputPattern[i,j]
);
% MixColumn
constraint forall(r in 0..R2-1, j in 0..3)
(
    MixColumnBackward(BackwardMaskX[r+1, 0, j], BackwardClassX[r+1, 0, j],
                      BackwardMaskX[r+1, 1, j], BackwardClassX[r+1, 1, j],
                      BackwardMaskX[r+1, 2, j], BackwardClassX[r+1, 2, j],
                      BackwardMaskX[r+1, 3, j], BackwardClassX[r+1, 3, j],
                      BackwardMaskSBX[r, 0, (j-0+4) mod 4], BackwardClassSBX[r, 0, (j-0+4) mod 4],
                      BackwardMaskSBX[r, 1, (j-1+4) mod 4], BackwardClassSBX[r, 1, (j-1+4) mod 4],
                      BackwardMaskSBX[r, 2, (j-2+4) mod 4], BackwardClassSBX[r, 2, (j-2+4) mod 4],
                      BackwardMaskSBX[r, 3, (j-3+4) mod 4], BackwardClassSBX[r, 3, (j-3+4) mod 4],
                      BackwardMaskAux[r,j], BackwardClassAux[r,j])
);
% SB Operation
constraint forall(r in 0..R2-1, i in 0..3, j in 0..3)
(
    SBOperation(BackwardMaskSBX[r,i,j], BackwardMaskX[r,i,j])
);
% ------------------------------------------------------------- %
array[0..R2, 0..3, 0..3] of var 0..3: BackAppMaskX;
array[0..R2, 0..3, 0..3] of var -2..15: BackAppClassX;
constraint forall(i in 0..R2, j in 0..3, k in 0..3)( LinkMaskClass(BackAppMaskX[i,j,k], BackAppClassX[i,j,k]) );

array [0..R2-1, 0..3, 0..3] of var 0..3: BackAppMaskSBX;
array [0..R2-1, 0..3, 0..3] of var -2..15: BackAppClassSBX;
constraint forall(i in 0..R2-1, j in 0..3, k in 0..3)( LinkMaskClass(BackAppMaskSBX[i,j,k], BackAppClassSBX[i,j,k]) );

array[0..R2-1, 0..3] of var 0..3: BackAppMaskAux;
array[0..R2-1, 0..3] of var -2..15: BackAppClassAux;
constraint forall(i in 0..R2-1, j in 0..3)( LinkMaskClass(BackAppMaskAux[i,j], BackAppClassAux[i,j]) );
% Initialise the middle round
constraint forall(i in 0..3, j in 0..3)
(
    if (ForwardMaskX[R1, i, j] <= BackwardMaskX[0, i, j]) then 
        BackAppMaskX[0,i,j] = ForwardMaskX[R1, i, j] /\
        BackAppClassX[0,i,j] = ForwardClassX[R1, i, j]
    else
        BackAppMaskX[0,i,j] = BackwardMaskX[0, i, j] /\
        BackAppClassX[0,i,j] = BackwardClassX[0, i, j]
    endif
);
% SB Operation
constraint forall(r in 0..R2-1, i in 0..3, j in 0..3)
(
    SBOperation(BackAppMaskX[r,i,j], BackAppMaskSBX[r,i,j])
);
% MixColumn
constraint forall(r in 0..R2-1, j in 0..3)
(
    MixColumnForward(BackAppMaskSBX[r,0,(j-0+4) mod 4], BackAppClassSBX[r,0,(j-0+4) mod 4],
                     BackAppMaskSBX[r,1,(j-1+4) mod 4], BackAppClassSBX[r,1,(j-1+4) mod 4],
                     BackAppMaskSBX[r,2,(j-2+4) mod 4], BackAppClassSBX[r,2,(j-2+4) mod 4],
                     BackAppMaskSBX[r,3,(j-3+4) mod 4], BackAppClassSBX[r,3,(j-3+4) mod 4],
                     BackAppMaskX[r+1,0,j], BackAppClassX[r+1,0,j],
                     BackAppMaskX[r+1,1,j], BackAppClassX[r+1,1,j],
                     BackAppMaskX[r+1,2,j], BackAppClassX[r+1,2,j],
                     BackAppMaskX[r+1,3,j], BackAppClassX[r+1,3,j],
                     BackAppMaskAux[r,j], BackAppClassAux[r,j])
);
% ------------------------------------------------------------- %
array[0..R1, 0..3, 0..3] of var 0..3: ForAppMaskX;
array[0..R1, 0..3, 0..3] of var -2..15: ForAppClassX;
constraint forall(i in 0..R1, j in 0..3, k in 0..3)( LinkMaskClass(ForAppMaskX[i,j,k], ForAppClassX[i,j,k]) );

array[0..R1-1, 0..3, 0..3] of var 0..3: ForAppMaskSBX;
array[0..R1-1, 0..3, 0..3] of var -2..15: ForAppClassSBX;
constraint forall(i in 0..R1-1, j in 0..3, k in 0..3)( LinkMaskClass(ForAppMaskSBX[i,j,k], ForAppClassSBX[i,j,k]) );

array[0..R1-1, 0..3] of var 0..3: ForAppMaskAux;
array[0..R1-1, 0..3] of var -2..15: ForAppClassAux;
constraint forall(i in 0..R1-1, j in 0..3)( LinkMaskClass(ForAppMaskAux[i,j], ForAppClassAux[i,j]) );
% Initialise the middle round
constraint forall(i in 0..3, j in 0..3)
(
    if (ForwardMaskX[R1, i, j] <= BackwardMaskX[0, i, j]) then 
        ForAppMaskX[R1,i,j] = ForwardMaskX[R1, i, j] /\
        ForAppClassX[R1,i,j] = ForwardClassX[R1, i, j]
    else
        ForAppMaskX[R1,i,j] = BackwardMaskX[0, i, j] /\
        ForAppClassX[R1,i,j] = BackwardClassX[0, i, j]
    endif
);
% MixColumn
constraint forall(r in 0..R1-1, j in 0..3)
(
    MixColumnBackward(ForAppMaskX[r+1,0,j], ForAppClassX[r+1,0,j],
                      ForAppMaskX[r+1,1,j], ForAppClassX[r+1,1,j],
                      ForAppMaskX[r+1,2,j], ForAppClassX[r+1,2,j],
                      ForAppMaskX[r+1,3,j], ForAppClassX[r+1,3,j],
                      ForAppMaskSBX[r,0,(j-0+4) mod 4], ForAppClassSBX[r,0,(j-0+4) mod 4],
                      ForAppMaskSBX[r,1,(j-1+4) mod 4], ForAppClassSBX[r,1,(j-1+4) mod 4],
                      ForAppMaskSBX[r,2,(j-2+4) mod 4], ForAppClassSBX[r,2,(j-2+4) mod 4],
                      ForAppMaskSBX[r,3,(j-3+4) mod 4], ForAppClassSBX[r,3,(j-3+4) mod 4],
                      ForAppMaskAux[r,j], ForAppClassAux[r,j])
);
% SB Operation
constraint forall(r in 0..R1-1, i in 0..3, j in 0..3)
(
     SBOperation(ForAppMaskSBX[r,i,j], ForAppMaskX[r,i,j])
);

var 0..(R1+R2+2)*48: contradict;
constraint contradict = sum(r in 0..R1, i in 0..3, j in 0..3)(bool2int((ForwardMaskX[r,i,j]+ForAppMaskX[r,i,j]>0) /\ (ForwardMaskX[r,i,j]+ForAppMaskX[r,i,j]<3) /\ (ForwardMaskX[r,i,j]!=ForAppMaskX[r,i,j]))) + sum(r in 0..R2, i in 0..3, j in 0..3)(bool2int((BackwardMaskX[r,i,j]+BackAppMaskX[r,i,j]>0) /\ (BackwardMaskX[r,i,j]+BackAppMaskX[r,i,j]<3) /\ (BackwardMaskX[r,i,j]!=BackAppMaskX[r,i,j])));
constraint contradict > 0;

solve satisfy;
% ------------------------------------------------------------- %
predicate LinkMaskClass(var 0..3: Mask, var -2..15: Class) = 
    if (Mask == 0) then Class == 0
    elseif (Mask == 1) then Class > 0
    elseif (Mask == 2) then Class == -1
    else Class = -2 endif
;

predicate SBOperation(var 0..3: MaskIn, var 0..3: MaskOut) = 
    MaskOut != 1 /\
    (MaskIn + MaskOut) in {0,3,4,6} /\
    MaskOut >= MaskIn /\
    (MaskOut - MaskIn) <= 1
;

predicate XOR(var 0..3: MaskA, var -2..15: ClassA, var 0..3: MaskB, var -2..15: ClassB, var 0..3: MaskC, var -2..15: ClassC) = 
    if (MaskA + MaskB > 2) then 
        (MaskC = 3) /\ (ClassC = -2)
    elseif (MaskA + MaskB = 1) then
        (MaskC = 1) /\ (ClassC = ClassA + ClassB)
    elseif ((MaskA == 0) /\ (MaskB == 0)) then
        (MaskC = 0) /\ (ClassC = 0)
    elseif (ClassA + ClassB < 0) then
        (MaskC = 2) /\ (ClassC = -1)
    elseif (ClassA == ClassB) then
        (MaskC = 0) /\ (ClassC = 0)
    else
        (MaskC = 1) /\
        ClassC = (bool2int((ClassA mod 2) != (ClassB mod 2)) + 
        bool2int(((ClassA div 2) mod 2) != ((ClassB div 2) mod 2)) * 2 + 
        bool2int(((ClassA div 4) mod 2) != ((ClassB div 4) mod 2)) * 4 +
        bool2int(((ClassA div 8) mod 2) != ((ClassB div 8) mod 2)) * 8)
    endif
;

predicate MixColumnForward(var 0..3: InMask1, var -2..15: InClass1, 
                           var 0..3: InMask2, var -2..15: InClass2, 
                           var 0..3: InMask3, var -2..15: InClass3, 
                           var 0..3: InMask4, var -2..15: InClass4, 
                           var 0..3: OutMask1, var -2..15: OutClass1, 
                           var 0..3: OutMask2, var -2..15: OutClass2, 
                           var 0..3: OutMask3, var -2..15: OutClass3, 
                           var 0..3: OutMask4, var -2..15: OutClass4, 
                           var 0..3: AuxiMask, var -2..15: AuxiClass) =
    % The First Row
    OutMask1 = InMask4 /\
    OutClass1 = InClass4
    /\
    % The Third Row
    OutMask3 = InMask2 /\
    OutClass3 = InClass2
    /\
    % Computing Aux
    % A: InMask2, InClass2
    % B: InMask3, InClass3
    % C: AuxiMask, AuxiClass
    XOR(InMask2, InClass2, InMask3, InClass3, AuxiMask, AuxiClass)
    /\
    % The Second Row
    % A: AuxiMask, AuxiClass
    % B: InMask1, InClass1
    % C: OutMask2, OutClass2
    XOR(AuxiMask, AuxiClass, InMask1, InClass1, OutMask2, OutClass2)
    /\
    % The Fourth Row
    % A: AuxiMask, AuxiClass
    % B: InMask4, InClass4
    % C: OutMask4, OutClass4
    XOR(AuxiMask, AuxiClass, InMask4, InClass4, OutMask4, OutClass4)
;

predicate MixColumnBackward(var 0..3: InMask1, var -2..15: InClass1, 
                           var 0..3: InMask2, var -2..15: InClass2, 
                           var 0..3: InMask3, var -2..15: InClass3, 
                           var 0..3: InMask4, var -2..15: InClass4, 
                           var 0..3: OutMask1, var -2..15: OutClass1, 
                           var 0..3: OutMask2, var -2..15: OutClass2, 
                           var 0..3: OutMask3, var -2..15: OutClass3, 
                           var 0..3: OutMask4, var -2..15: OutClass4, 
                           var 0..3: AuxiMask, var -2..15: AuxiClass) =
    % The Second Row
    OutMask2 = InMask3 /\
    OutClass2 = InClass3
    /\
    % The Fourth Row
    OutMask4 = InMask1 /\
    OutClass4 = InClass1
    /\
    % Computing Aux
    % A: InMask1 InClass1
    % B: InMask4 InClass4
    % C: AuxiMask AuxiClass
    XOR(InMask1, InClass1, InMask4, InClass4, AuxiMask, AuxiClass)
    /\
    % The First Row
    % A: AuxiMask AuxiClass
    % B: InMask2 InClass2
    % C: OutMask1 OutClass1
    XOR(AuxiMask, AuxiClass, InMask2, InClass2, OutMask1, OutClass1)
    /\
    % The Third Row
    % A: AuxiMask AuxiClass
    % B: InMask3 InClass3
    % C: OutMask3 OutClass3
    XOR(AuxiMask, AuxiClass, InMask3, InClass3, OutMask3, OutClass3)
;
