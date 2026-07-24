import {
  assert,
  gtxn,
  LogicSig,
  Txn,
} from "@algorandfoundation/algorand-typescript";

import {
  mimc,
  MimcConfigurations,
} from "@algorandfoundation/algorand-typescript/op";

export class SignalVerifier extends LogicSig {
  program(): boolean {
    const appl = gtxn.ApplicationCallTxn(Txn.groupIndex + 2);
    const signalHash = appl.appArgs(1).slice(2);
    const signalValues = appl.appArgs(3).slice(2);

    const computed = mimc(MimcConfigurations.BLS12_381Mp111, signalValues);
    assert(computed === signalHash);
    return true;
  }
}
