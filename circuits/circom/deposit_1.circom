pragma circom 2.1.5;

include "./deposit.circom";

component main {public [asset, receivers]}  = Deposit(1);

