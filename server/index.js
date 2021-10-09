const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;

const EC = require('elliptic').ec;          // elliptic curve lib
const ec = new EC('secp256k1');
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

// generate keys for accounts
const numAccounts = 3;
const amounts = [100,50,75];
let balances = {};
let publicKeys = {};
for (let i=0; i<numAccounts; i++) {
  let key = ec.genKeyPair();
  let privateKey = key.getPrivate().toString(16);
  let publicKey = key.getPublic().encode('hex');
  let address = publicKey.substring(publicKey.length-40,publicKey.length);  // define address as last 40 characters

  balances[address] = amounts[i];
  publicKeys[address] = publicKey;

  // log public keys and balances to console
  console.log(i+1);
  console.log('Account:\t' + address.toString() + '\tBalance:\t' + balances[address].toString() );

  // log private key to console for later use
  console.log('Private Key for Account:\t' + privateKey.toString());
}

// const balances = {
//   "1": 100,
//   "2": 50,
//   "3": 75,
// }

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, privateKey} = req.body;

  // get key from private key
  const key = ec.keyFromPrivate(privateKey);

  // create signature from amount and the private key
  const msgHash = SHA256(amount);
  const signature = key.sign(msgHash.toString());

  // verify the signature using the public key
  const publicKey = publicKeys[sender];
  const keyVerify = ec.keyFromPublic(publicKey, 'hex');
  const msgHashVerify = SHA256(amount).toString();
  const verified = keyVerify.verify(msgHashVerify, signature)

  if (verified) {
    // keys match
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
    console.log('Transaction Successful!')
  }
  else {
    console.log('ERROR: Incorrect Private Key!')
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
