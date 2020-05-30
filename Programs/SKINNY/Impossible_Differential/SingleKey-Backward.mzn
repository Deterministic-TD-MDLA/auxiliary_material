int: R;

array[0..R, 0..3, 0..3] of var 0..3: DeltaX;
array[0..R, 0..3, 0..3] of var -2..15: ClassX;
constraint forall(i in 0..R, j in 0..3, k in 0..3)( LinkDeltaClass(DeltaX[i,j,k], ClassX[i,j,k]) );

array[0..R-1, 0..3, 0..3] of var 0..3: DeltaSBX;
array[0..R-1, 0..3, 0..3] of var -2..15: ClassSBX;
constraint forall(i in 0..R-1, j in 0..3, k in 0..3)( LinkDeltaClass(DeltaSBX[i,j,k], ClassSBX[i,j,k]) );
% ------------------------------------------------------------- %

% MixColumn
constraint forall(r in 0..R-1, j in 0..3)
(
    % The First Column
    DeltaSBX[R-1-r, 0, (j-0+4) mod 4] = DeltaX[R-r,1,j] /\
    ClassSBX[R-1-r, 0, (j-0+4) mod 4] = ClassX[R-r,1,j]
    /\
    % The Third Column
    % A: DeltaX[R-r, 1, j] ClassX[R-r, 1, j]
    % B: DeltaX[R-r, 3, j] ClassX[R-r, 3, j]
    % C: DeltaSBX[R-1-r, 2, (j-2+4) mod 4] ClassSBX[R-1-r, 2, (j-2+4) mod 4]
    XOR(DeltaX[R-r, 1, j], ClassX[R-r, 1, j], DeltaX[R-r, 3, j], ClassX[R-r, 3, j], DeltaSBX[R-1-r, 2, (j-2+4) mod 4], ClassSBX[R-1-r, 2, (j-2+4) mod 4])
    /\
    % The Second Column
    % A: DeltaSBX[R-1-r, 2, (j-2+4) mod 4] ClassSBX[R-1-r, 2, (j-2+4) mod 4]
    % B: DeltaX[R-r,2,j] ClassX[R-r,2,j]
    % C: DeltaSBX[R-1-r,1,(j-1+4) mod 4] ClassSBX[R-1-r,1,(j-1+4) mod 4]
    XOR(DeltaSBX[R-1-r, 2, (j-2+4) mod 4], ClassSBX[R-1-r, 2, (j-2+4) mod 4], DeltaX[R-r,2,j], ClassX[R-r,2,j], DeltaSBX[R-1-r,1,(j-1+4) mod 4], ClassSBX[R-1-r,1,(j-1+4) mod 4])
    /\
    % The Fourth Column
    % A: DeltaX[R-r,0,j] ClassX[R-r,0,j]
    % B: DeltaX[R-r,3,j] ClassX[R-r,3,j]
    % C: DeltaSBX[R-1-r,3,(j-3+4) mod 4] ClassSBX[R-1-r,3,(j-3+4) mod 4]
    XOR(DeltaX[R-r,0,j], ClassX[R-r,0,j], DeltaX[R-r,3,j], ClassX[R-r,3,j], DeltaSBX[R-1-r,3,(j-3+4) mod 4], ClassSBX[R-1-r,3,(j-3+4) mod 4])
);
% ----------------------------- %

% SB Operation
constraint forall(r in 0..R-1, i in 0..3, j in 0..3)
(
    % A: DeltaSBX[R-1-r,i,j] ClassSBX[R-1-r,i,j] 
    % B: DeltaX[R-1-r,i,j] ClassX[R-1-r,i,j]
    SBOperation(DeltaSBX[R-1-r,i,j], DeltaX[R-1-r,i,j])
);
% ----------------------------- %
var 0..48: outputdiff;
constraint outputdiff = sum(r in R..R, i in 0..3, j in 0..3)(DeltaX[r,i,j]);
constraint outputdiff != 0;

% Condition
constraint DeltaX[0,0,0] = 0;

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