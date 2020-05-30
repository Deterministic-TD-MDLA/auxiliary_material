int: R;

array[0..R, 0..3, 0..3] of var 0..3: DeltaX;
array[0..R, 0..3, 0..3] of var -2..15: ClassX;
constraint forall(i in 0..R, j in 0..3, k in 0..3)( LinkDeltaClass(DeltaX[i,j,k], ClassX[i,j,k]) );

array[0..R-1, 0..3, 0..3] of var 0..3: DeltaSBX;
array[0..R-1, 0..3, 0..3] of var -2..15: ClassSBX;
constraint forall(i in 0..R-1, j in 0..3, k in 0..3)( LinkDeltaClass(DeltaSBX[i,j,k], ClassSBX[i,j,k]) );
% ----------------------------- %

% SB Operation
constraint forall(r in 0..0, i in 0..3, j in 0..3) % The First Round
(
    DeltaSBX[r,i,j] = DeltaX[r,i,j] /\
    ClassSBX[r,i,j] = ClassX[r,i,j]
);
constraint forall(r in 1..R-1, i in 0..3, j in 0..3)
(
    SBOperation(DeltaX[r,i,j], DeltaSBX[r,i,j])
);
% ----------------------------- %

% MixColumn
constraint forall(r in 0..R-1, j in 0..3)
(
    % The Second Row
    DeltaX[r+1, 1, j] = DeltaSBX[r, 0, (j-0+4) mod 4] /\
    ClassX[r+1, 1, j] = ClassSBX[r, 0, (j-0+4) mod 4]
    /\
    % The Third Row
    % A: DeltaSBX[r,1,(j-1+4) mod 4] ClassSBX[r,1,(j-1+4) mod 4]
    % B: DeltaSBX[r,2,(j-2+4) mod 4] ClassSBX[r,2,(j-2+4) mod 4]
    % C: DeltaX[r+1,2,j] ClassX[r+1,2,j]
    XOR(DeltaSBX[r,1,(j-1+4) mod 4], ClassSBX[r,1,(j-1+4) mod 4], DeltaSBX[r,2,(j-2+4) mod 4], ClassSBX[r,2,(j-2+4) mod 4], DeltaX[r+1,2,j], ClassX[r+1,2,j])
    /\
    % The Fourth Row
    % A: DeltaSBX[r,0,(j-0+4) mod 4] ClassSBX[r,0,(j-0+4) mod 4]
    % B: DeltaSBX[r,2,(j-2+4) mod 4] ClassSBX[r,2,(j-2+4) mod 4]
    % C: DeltaX[r+1,3,j] ClassX[r+1,3,j]
    XOR(DeltaSBX[r,0,(j-0+4) mod 4], ClassSBX[r,0,(j-0+4) mod 4], DeltaSBX[r,2,(j-2+4) mod 4], ClassSBX[r,2,(j-2+4) mod 4], DeltaX[r+1,3,j], ClassX[r+1,3,j])
    /\
    % The First Row
    % A: DeltaX[r+1,3,j] ClassX[r+1,3,j]
    % B: DeltaSBX[r,3,(j-3+4) mod 4] ClassSBX[r,3,(j-3+4) mod 4]
    % C: DeltaX[r+1,0,j] ClassX[r+1,0,j]
    XOR(DeltaX[r+1,3,j], ClassX[r+1,3,j], DeltaSBX[r,3,(j-3+4) mod 4], ClassSBX[r,3,(j-3+4) mod 4], DeltaX[r+1,0,j], ClassX[r+1,0,j])
);

var 0..48: inputdiff;
constraint inputdiff = sum(r in 0..0, i in 0..3, j in 0..3)(DeltaX[r,i,j]);
constraint inputdiff != 0;

% Condition
constraint DeltaX[R,0,0] = 0;

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
    if (DeltaA + DeltaB > 2) then 
        (DeltaC = 3) /\ (ClassC = -2)
    elseif (DeltaA + DeltaB = 1) then
        (DeltaC = 1) /\ (ClassC = ClassA + ClassB)
    elseif ((DeltaA == 0) /\ (DeltaB = 0)) then
        (DeltaC = 0) /\ (ClassC = 0)
    elseif (ClassA + ClassB < 0) then
        (DeltaC = 2) /\ (ClassC = -1)
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