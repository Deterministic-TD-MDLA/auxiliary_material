int: R;
array[0..7, 0..7] of 0..7: RotationParaInv;

array[0..R, 0..7, 0..7] of var 0..3: DeltaX;
array[0..R, 0..7, 0..7] of var -2..15: ClassX;
constraint forall(i in 0..R, j in 0..7, k in 0..7)(LinkDeltaClass(DeltaX[i,j,k], ClassX[i,j,k]));

array[0..R-1, 0..7, 0..7] of var 0..3: DeltaSBX;
array[0..R-1, 0..7, 0..7] of var -2..15: ClassSBX;
constraint forall(i in 0..R-1, j in 0..7, k in 0..7)(LinkDeltaClass(DeltaSBX[i,j,k], ClassSBX[i,j,k]));

array[0..R, 0..7, 0..7] of var 0..3: DeltaY;
array[0..R, 0..7, 0..7] of var -2..15: ClassY;
constraint forall(i in 0..R, j in 0..7, k in 0..7)(LinkDeltaClass(DeltaY[i,j,k], ClassY[i,j,k]));

array[0..R, 0..3, 0..7] of var 0..3: DeltaAux;
array[0..R, 0..3, 0..7] of var -2..15: ClassAux;
constraint forall(i in 0..R, j in 0..3, k in 0..7)(LinkDeltaClass(DeltaAux[i,j,k], ClassAux[i,j,k]));
% ------------------------------------------------------------- %
% MixColumn
constraint forall(r in 0..R, i in 0..1, j in 0..7)
(
    % A: DeltaX[r, 4*i, j] ClassX[r, 4*i, j]
    % B: DeltaX[r, 4*i+1, j] ClassX[r, 4*i+1, j] 
    % C: DeltaAux[r, 2*i, j] ClassAux[r, 2*i, j]
    XOR(DeltaX[r, 4*i, j], ClassX[r, 4*i, j], DeltaX[r, 4*i+1, j], ClassX[r, 4*i+1, j], DeltaAux[r, 2*i, j], ClassAux[r, 2*i, j])
    /\
    % A: DeltaX[r, 4*i+2, j] ClassX[r, 4*i+2, j]
    % B: DeltaX[r, 4*i+3, j] ClassX[r, 4*i+3, j]
    % C: DeltaAux[r, 2*i+1, j] ClassAux[r, 2*i+1, j]
    XOR(DeltaX[r, 4*i+2, j], ClassX[r, 4*i+2, j], DeltaX[r, 4*i+3, j], ClassX[r, 4*i+3, j], DeltaAux[r, 2*i+1, j], ClassAux[r, 2*i+1, j])
    /\
    % A: DeltaAux[r, 2*i, j] ClassAux[r, 2*i, j]
    % B: DeltaX[r, 4*i+3, j] ClassX[r, 4*i+3, j]
    % C: DeltaY[r, 4*i, j] ClassY[r, 4*i, j]
    XOR(DeltaAux[r, 2*i, j], ClassAux[r, 2*i, j], DeltaX[r, 4*i+3, j], ClassX[r, 4*i+3, j], DeltaY[r, 4*i, j], ClassY[r, 4*i, j])
    /\
    % A: DeltaAux[r, 2*i, j] ClassAux[r, 2*i, j]
    % B: DeltaX[r, 4*i+2, j] ClassX[r, 4*i+2, j]
    % C: DeltaY[r, 4*i+1, j] ClassY[r, 4*i+1, j]
    XOR(DeltaAux[r, 2*i, j], ClassAux[r, 2*i, j], DeltaX[r, 4*i+2, j], ClassX[r, 4*i+2, j], DeltaY[r, 4*i+1, j], ClassY[r, 4*i+1, j])
    /\
    % A: DeltaAux[r, 2*i+1, j] ClassAux[r, 2*i+1, j]
    % B: DeltaX[r, 4*i+1, j] ClassX[r, 4*i+1, j]
    % C: DeltaY[r, 4*i+2, j] ClassY[r, 4*i+2, j]
    XOR(DeltaAux[r, 2*i+1, j], ClassAux[r, 2*i+1, j], DeltaX[r, 4*i+1, j], ClassX[r, 4*i+1, j], DeltaY[r, 4*i+2, j], ClassY[r, 4*i+2, j])
    /\
    % A: DeltaAux[r, 2*i+1, j] ClassAux[r, 2*i+1, j]
    % B: DeltaX[r, 4*i, j] ClassX[r, 4*i, j]
    % C: DeltaY[r, 4*i+3, j] ClassY[r, 4*i+3, j]
    XOR(DeltaAux[r, 2*i+1, j], ClassAux[r, 2*i+1, j], DeltaX[r, 4*i, j], ClassX[r, 4*i, j], DeltaY[r, 4*i+3, j], ClassY[r, 4*i+3, j])
);

% XOR
constraint forall(r in 0..R-1, i in 4..7, j in 0..7)
(
    DeltaSBX[r,i,j] = DeltaY[r+1, i-4, RotationParaInv[i,j]] /\
    ClassSBX[r,i,j] = ClassY[r+1, i-4, RotationParaInv[i,j]]
);
constraint forall(r in 0..R-1, i in 0..3, j in 0..7)
(
    % A: DeltaY[r+1,i,RotationParaInv[i,j]] ClassY[r+1,i,RotationParaInv[i,j]]
    % B: DeltaY[r+1,i+4, RotationParaInv[i,j]] ClassY[r+1,i+4, RotationParaInv[i,j]]
    % C: DeltaSBX[r,i,j] ClassSBX[r,i,j]
    XOR(DeltaY[r+1,i,RotationParaInv[i,j]], ClassY[r+1,i,RotationParaInv[i,j]], DeltaY[r+1,i+4, RotationParaInv[i,j]], ClassY[r+1,i+4, RotationParaInv[i,j]], DeltaSBX[r,i,j], ClassSBX[r,i,j])
);

% SBOperation
constraint forall(r in 0..R-1, i in 0..7, j in 0..7)
(
    SBOperation(DeltaSBX[r,i,j], DeltaX[r,i,j])
);

var 0..192: outputdiff;
constraint outputdiff = sum(r in R..R, i in 0..7, j in 0..7)(DeltaX[r,i,j]);
constraint outputdiff != 0;

% Condition
constraint DeltaY[0, 0, 0] = 0;

solve satisfy;
% ------------------------------------------------------------- %
predicate LinkDeltaClass(var 0..3: Delta, var -2..15: Class) = 
    if (Delta == 0) then Class == 0
    elseif (Delta == 1) then Class > 0
    elseif (Delta == 2) then Class == -1
    else Class = -2
    endif
;

predicate SBOperation(var 0..3: DeltaIn, var 0..3: DeltaOut) = 
DeltaOut != 1 /\
(DeltaIn + DeltaOut) in {0,3,4,6} /\
DeltaOut >= DeltaIn /\
(DeltaOut - DeltaIn) <= 1
;

predicate XOR(var 0..3: DeltaA, var -2..15: ClassA, var 0..3: DeltaB, var -2..15: ClassB, var 0..3: DeltaC, var -2..15: ClassC) = 
    if ((DeltaA == 3) \/ (DeltaB == 3)) then
        (DeltaC = 3) /\ (ClassC = -2)
    elseif (DeltaA == 0) then
        (DeltaC = DeltaB) /\ (ClassC = ClassB)
    elseif (DeltaB == 0) then
        (DeltaC = DeltaA) /\ (ClassC = ClassA)
    elseif ((DeltaA == 2) /\ (DeltaB == 2)) then
        (DeltaC = 3) /\ (ClassC = -2)
    elseif ((DeltaA == 2) /\ (DeltaB == 1)) then
        (DeltaC = 3) /\ (ClassC = -2)
    elseif ((DeltaA == 1) /\ (DeltaB == 2)) then
        (DeltaC = 3) /\ (ClassC = -2)
    elseif (ClassA == ClassB) then
        (DeltaC = 0) /\ (ClassC = 0)
    else
        (DeltaC = 1) /\ 
        ClassC = (bool2int((ClassA mod 2) != (ClassB mod 2)) + 
        bool2int(((ClassA div 2) mod 2) != ((ClassB div 2) mod 2)) * 2 + 
        bool2int(((ClassA div 4) mod 2) != ((ClassB div 4) mod 2)) * 4 +
        bool2int(((ClassA div 8) mod 2) != ((ClassB div 8) mod 2)) * 8)
    endif
;