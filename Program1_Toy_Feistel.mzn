include "globals.mzn";

int: R;

array[0..R, 0..1] of var 0..4: DeltaX;
array[0..R, 0..1] of var -1..15: ClassX;
array[0..R, 0..1] of var 0..30: XiX;
constraint forall(i in 0..R, j in 0..1)( LinkDeltaClassXi(DeltaX[i,j], ClassX[i,j], XiX[i,j]) );

array[0..R-1] of var 0..4: DeltaY;
array[0..R-1] of var -1..15: ClassY;
array[0..R-1] of var 0..30: XiY;
constraint forall(i in 0..R-1)( LinkDeltaClassXi(DeltaY[i], ClassY[i], XiY[i]) );
% ------------------------------------------------------------- %
% S-box
constraint forall(r in 0..R-1)
(
    NewSBOperation(DeltaX[r,1], DeltaY[r])
);

% Left branch
constraint forall(r in 0..R-1)
(
    DeltaX[r+1, 0] = DeltaX[r, 1] /\
    ClassX[r+1, 0] = ClassX[r, 1] /\
    XiX[r+1, 0] = XiX[r, 1]
);

% XOR
constraint forall(r in 0..R-1)
(
    XOR(DeltaX[r,0], ClassX[r,0], XiX[r,0], DeltaY[r], ClassY[r], XiY[r], DeltaX[r+1,1], ClassX[r+1,1], XiX[r+1,1])
);

% All different after the nonlinear operation
array[0..R] of var 0..30: NonZeroVariedClass;
constraint NonZeroVariedClass[0] = XiX[0,1];
constraint forall(i in 1..R)
(
    NonZeroVariedClass[i] = XiY[i-1]
);
constraint alldifferent_except_0(NonZeroVariedClass);

% Restrict the input difference
var 0..8: inputdiff;
constraint inputdiff = sum(r in 0..0, i in 0..1)(DeltaX[r,i]);
constraint inputdiff != 0;

% Objective function
constraint DeltaX[R,0] != 4;

solve satisfy;
% ------------------------------------------------------------- %
predicate LinkDeltaClassXi(var 0..4: Delta, var -1..15: Class, var 0..30: Xi) = 
    if (Delta = 0) then Class = 0 /\ Xi = 0
    elseif (Delta = 1) then Class > 0 /\ Xi = 0
    elseif (Delta = 2) then Class = 0 /\ Xi > 0
    elseif (Delta = 3) then Class > 0 /\ Xi > 0
    else Class = -1 /\ Xi = 0 
    endif
;

predicate NewSBOperation(var 0..4: DeltaIn, var 0..4: DeltaOut) = 
    DeltaOut != 1 /\
    DeltaOut != 3 /\
    DeltaOut >= DeltaIn /\
    DeltaOut - DeltaIn <= 1
;

predicate XOR(var 0..4: DeltaA, var -1..15: ClassA, var 0..30: XiA,
              var 0..4: DeltaB, var -1..15: ClassB, var 0..30: XiB,
              var 0..4: DeltaC, var -1..15: ClassC, var 0..30: XiC) = 
    if (DeltaA + DeltaB > 4) then %
        (DeltaC = 4) /\ (ClassC = -1) /\ (XiC = 0) %
    elseif ((DeltaA = 0) /\ (DeltaB = 0)) then %
        (DeltaC = 0) /\ (ClassC = 0) /\ (XiC = 0) %
    elseif (DeltaA + DeltaB = 1) then %
        (DeltaC = 1) /\ (ClassC = ClassA + ClassB) /\ (XiC = 0) %
    elseif (DeltaA + DeltaB = 3) then %
        (DeltaC = 3) /\ (ClassC = ClassA + ClassB) /\ (XiC = XiA + XiB) %
    elseif ((DeltaA = 4) \/ (DeltaB = 4)) then %
        (DeltaC = 4) /\ (ClassC = -1) /\ (XiC = 0) %
    elseif ((DeltaA = 2) /\ (DeltaB = 2)) then %
        (DeltaC = 4) /\ (ClassC = -1) /\ (XiC = 0) %
    elseif ((DeltaA + DeltaB = 4) /\ (ClassA = ClassB)) then %
        (DeltaC = 2) /\ (ClassC = 0) /\ (XiC = XiA + XiB) %
    elseif (DeltaA + DeltaB = 4) then %
        (DeltaC = 3) /\ (XiC = XiA + XiB) /\ %
        ClassC = bool2int((ClassA mod 2) != (ClassB mod 2)) + %
        bool2int(((ClassA div 2) mod 2) != ((ClassB div 2) mod 2)) * 2 + %
        bool2int(((ClassA div 4) mod 2) != ((ClassB div 4) mod 2)) * 4 + %
        bool2int(((ClassA div 8) mod 2) != ((ClassB div 8) mod 2)) * 8 %
    elseif ((DeltaA = 2) \/ (DeltaB = 2)) then %
        (DeltaC = 2) /\ (ClassC = 0) /\ (XiC = XiA + XiB) %
    elseif (ClassA = ClassB) then
        (DeltaC = 0) /\ (ClassC = 0) /\ (XiC = 0)
    else 
        (DeltaC = 1) /\ (XiC = 0) /\
        ClassC = bool2int((ClassA mod 2) != (ClassB mod 2)) + 
        bool2int(((ClassA div 2) mod 2) != ((ClassB div 2) mod 2)) * 2 +
        bool2int(((ClassA div 4) mod 2) != ((ClassB div 4) mod 2)) * 4 + 
        bool2int(((ClassA div 8) mod 2) != ((ClassB div 8) mod 2)) * 8
    endif
;


