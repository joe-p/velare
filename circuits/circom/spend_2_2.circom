pragma circom 2.1.5;

include "./spend.circom";

component main {public [spender, asset, receivers]}  = Spend(2, 2);

