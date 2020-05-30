int: R;

array[0..R, 0..3, 0..3] of var 0..3: MaskX;
array[0..R, 0..3, 0..3] of var -2..15: ClassX;
constraint forall(i in 0..R, j in 0..3, k in 0..3)( LinkMaskClass(MaskX[i,j,k], ClassX[i,j,k]) );

array[0..R-1, 0..3, 0..3] of var 0..3: MaskSBX;
array[0..R-1, 0..3, 0..3] of var -2..15: ClassSBX;
constraint forall(i in 0..R-1, j in 0..3, k in 0..3)( LinkMaskClass(MaskSBX[i,j,k], ClassSBX[i,j,k]) );

array[0..R-1, 0..3] of var 0..3: MaskAux;
array[0..R-1, 0..3] of var -2..15: ClassAux;
constraint forall(i in 0..R-1, j in 0..3)( LinkMaskClass(MaskAux[i,j], ClassAux[i,j]) );
% ----------------------------- %
% SB Operation
constraint forall(r in 0..0, i in 0..3, j in 0..3)
(
    MaskSBX[r,i,j] = MaskX[r,i,j] /\
    ClassSBX[r,i,j] = ClassX[r,i,j]
);
constraint forall(r in 1..R-1, i in 0..3, j in 0..3)
(
    SBOperation(MaskX[r,i,j], MaskSBX[r,i,j])
);
% ----------------------------- %

% MixColumn
constraint forall(r in 0..R-1, j in 0..3)
(
    % The First Row
    MaskX[r+1, 0, j] = MaskSBX[r, 3, (j-3+4) mod 4] /\
    ClassX[r+1, 0, j] = ClassSBX[r, 3, (j-3+4) mod 4]
    /\
    % The Third Row
    MaskX[r+1, 2, j] = MaskSBX[r, 1, (j-1+4) mod 4] /\
    ClassX[r+1, 2, j] = ClassSBX[r, 1, (j-1+4) mod 4]
    /\
    % Computing Aux
    % A: MaskSBX[r, 1, (j-1+4) mod 4] ClassSBX[r, 1, (j-1+4) mod 4]
    % B: MaskSBX[r, 2, (j-2+4) mod 4] ClassSBX[r, 2, (j-2+4) mod 4]
    % C: MaskAux[r,j] ClassAux[r,j]
    XOR(MaskSBX[r, 1, (j-1+4) mod 4], ClassSBX[r, 1, (j-1+4) mod 4], MaskSBX[r, 2, (j-2+4) mod 4], ClassSBX[r, 2, (j-2+4) mod 4], MaskAux[r,j], ClassAux[r,j])
    /\
    % The Second Row
    % A: MaskAux[r,j] ClassAux[r,j]
    % B: MaskSBX[r, 0, (j-0+4) mod 4] ClassSBX[r, 0, (j-0+4) mod 4]
    % C: MaskX[r+1, 1, j] ClassX[r+1, 1, j]
    XOR(MaskAux[r,j], ClassAux[r,j], MaskSBX[r, 0, (j-0+4) mod 4], ClassSBX[r, 0, (j-0+4) mod 4], MaskX[r+1, 1, j], ClassX[r+1, 1, j])
    /\
    % The Fourth Row
    % A: MaskAux[r,j] ClassAux[r,j]
    % B: MaskSBX[r, 3, (j-3+4) mod 4] ClassSBX[r, 3, (j-3+4) mod 4]
    % C: MaskX[r+1, 3, j] ClassX[r+1, 3, j]
    XOR(MaskAux[r,j], ClassAux[r,j], MaskSBX[r, 3, (j-3+4) mod 4], ClassSBX[r, 3, (j-3+4) mod 4], MaskX[r+1, 3, j], ClassX[r+1, 3, j])
);

var 0..48: inputmask;
constraint inputmask = sum(r in 0..0, i in 0..3, j in 0..3)(MaskX[r,i,j]);
constraint inputmask != 0;

constraint MaskX[R,0,0] = 0;

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
