import { Transaction, Keypair } from './src';

const sender = Keypair.generate();
const tx = Transaction.createTransfer(sender, "recipient", 1, 0);
tx.sign(sender);
console.log(tx.toString());
