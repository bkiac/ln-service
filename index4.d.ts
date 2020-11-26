

### addPeer

Add a peer if possible (not self, or already connected)

Requires `peers:write` permission

`timeout` is not supported in LND 0.11.1 and below

    {
      is_temporary?: <Add Peer as Temporary Peer boolean> // Default: false
      lnd: <Authenticated LND>
      public_key: <Public Key Hex string>
      retry_count?: <Retry Count number>
      retry_delay?: <Delay Retry By Milliseconds number>
      socket: <Host Network Address And Optional Port string> // ip:port
      timeout?: <Connection Attempt Timeout Milliseconds number>
    }

    @returns via cbk or Promise

Example:

```node
const {addPeer} = require('ln-service');
const socket = hostIp + ':' + portNumber;
await addPeer({lnd, socket, public_key: publicKeyHexString});
```

### authenticatedLndGrpc

Initiate a gRPC API Methods Object for authenticated methods

Both the cert and macaroon expect the entire serialized LND generated file

    {
      cert?: <Base64 or Hex Serialized LND TLS Cert>
      macaroon: <Base64 or Hex Serialized Macaroon string>
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
        autopilot: <Autopilot API Methods Object>
        chain: <ChainNotifier API Methods Object>
        default: <Default API Methods Object>
        invoices: <Invoices API Methods Object>
        router: <Router API Methods Object>
        signer: <Signer Methods API Object>
        tower_client: <Watchtower Client Methods Object>
        tower_server: <Watchtower Server Methods API Object>
        wallet: <WalletKit gRPC Methods API Object>
        version: <Version Methods API Object>
      }
    }

Example:

```node
const lnService = require('ln-service');
const {lnd} = lnService.authenticatedLndGrpc({
  cert: 'base64 encoded tls.cert',
  macaroon: 'base64 encoded admin.macaroon',
  socket: '127.0.0.1:10009',
});
const wallet = await lnService.getWalletInfo({lnd});
```

### broadcastChainTransaction

Publish a raw blockchain transaction to Blockchain network peers

Requires LND built with `walletrpc` tag

    {
      description?: <Transaction Label string>
      lnd: <Authenticated LND>
      transaction: <Transaction Hex string>
    }

    @returns via cbk or Promise
    {
      id: <Transaction Id Hex string>
    }

Example:

```node
const {broadcastChainTransaction} = require('ln-service');
const transaction = hexEncodedTransactionString;

// Broadcast transaction to the p2p network
const {id} = await broadcastChainTransaction({lnd, transaction});
```

### calculateHops

Calculate hops between start and end nodes

    {
      channels: [{
        capacity: <Capacity Tokens number>
        id: <Standard Channel Id string>
        policies: [{
          base_fee_mtokens: <Base Fee Millitokens string>
          cltv_delta: <CLTV Delta number>
          fee_rate: <Fee Rate number>
          is_disabled: <Channel is Disabled boolean>
          max_htlc_mtokens: <Maximum HTLC Millitokens string>
          min_htlc_mtokens: <Minimum HTLC Millitokens string>
          public_key: <Public Key Hex string>
        }]
      }]
      end: <End Public Key Hex string>
      ignore?: [{
        channel?: <Standard Format Channel Id string>
        public_key: <Public Key Hex string>
      }]
      mtokens: <Millitokens number>
      start: <Start Public Key Hex string>
    }

    @throws
    <Error>

    @returns
    {
      hops?: [{
        base_fee_mtokens: <Base Fee Millitokens string>
        channel: <Standard Channel Id string>
        channel_capacity: <Channel Capacity Tokens number>
        cltv_delta: <CLTV Delta number>
        fee_rate: <Fee Rate number>
        public_key: <Public Key Hex string>
      }]
    }

Example:

```node
const {calculateHops, getNetworkGraph, getIdentity} = require('ln-service');
const {channels} = await getNetworkGraph;
const end = 'destinationPublicKeyHexString';
const start = (await getIdentity({lnd})).public_key;_
const const {hops} = calculateHops({channels, end, start, mtokens: '1000'});
```

### calculatePaths

Calculate multiple routes to a destination

    {
      channels: [{
        capacity: <Capacity Tokens number>
        id: <Standard Channel Id string>
        policies: [{
          base_fee_mtokens: <Base Fee Millitokens string>
          cltv_delta: <CLTV Delta number>
          fee_rate: <Fee Rate number>
          is_disabled: <Channel is Disabled boolean>
          max_htlc_mtokens: <Maximum HTLC Millitokens string>
          min_htlc_mtokens: <Minimum HTLC Millitokens string>
          public_key: <Public Key Hex string>
        }]
      }]
      end: <End Public Key Hex string>
      limit?: <Paths To Return Limit number>
      mtokens: <Millitokens number>
      start: <Start Public Key Hex string>
    }

    @throws
    <Error>

    @returns
    {
      paths?: [{
        hops: [{
          base_fee_mtokens: <Base Fee Millitokens string>
          channel: <Standard Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          cltv_delta: <CLTV Delta number>
          fee_rate: <Fee Rate number>
          public_key: <Public Key Hex string>
        }]
      }]
    }

Example:

```node
const {calculatePaths, getNetworkGraph, getIdentity} = require('ln-service');
const {channels} = await getNetworkGraph;
const end = 'destinationPublicKeyHexString';
const start = (await getIdentity({lnd})).public_key;
const const {paths} = calculatePaths({channels, end, start, mtokens: '1000'});
```

### cancelHodlInvoice

Cancel an invoice

  This call can cancel both HODL invoices and also void regular invoices

  Requires LND built with `invoicesrpc`

  Requires `invoices:write` permission

    {
      id: <Payment Preimage Hash Hex string>
      lnd: <Authenticated RPC LND>
    }

Example:

```node
const {cancelHodlInvoice} = require('ln-service');
const id = paymentRequestPreimageHashHexString;
const await cancelHodlInvoice({id, lnd});
```

### cancelPendingChannel

Cancel an external funding pending channel

    {
      id: <Pending Channel Id Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:
```node
const {cancelPendingChannel, openChannels} = require('ln-service');

const channelsToOpen = {capacity: 1e6, partner_public_key: publicKey}?;

const {pending} = await openChannels({lnd, channels: channelsToOpen});

const id? = pending;

// Cancel the pending channel open request
await cancelPendingChannel({id, lnd});
```

### changePassword

Change wallet password

Requires locked LND and unauthenticated LND connection

    {
      current_password: <Current Password string>
      lnd: <Unauthenticated LND>
      new_password: <New Password string>
    }

    @returns via cbk or Promise

Example:

```node
const {changePassword} = require('ln-service');
await changePassword({lnd, current_password: pass, new_password: newPass});
```

### closeChannel

Close a channel.

Either an id or a transaction id / transaction output index is required

If cooperatively closing, pass a public key and socket to connect

Requires `info:read`, `offchain:write`, `onchain:write`, `peers:write` permissions

    {
      address?: <Request Sending Local Channel Funds To Address string>
      id?: <Standard Format Channel Id string>
      is_force_close?: <Is Force Close boolean>
      lnd: <Authenticated LND>
      public_key?: <Peer Public Key string>
      socket?: <Peer Socket string>
      target_confirmations?: <Confirmation Target number>
      tokens_per_vbyte?: <Tokens Per Virtual Byte number>
      transaction_id?: <Transaction Id Hex string>
      transaction_vout?: <Transaction Output Index number>
    }

    @returns via cbk or Promise
    {
      transaction_id: <Closing Transaction Id Hex string>
      transaction_vout: <Closing Transaction Vout number>
    }

Example:

```node
const {closeChannel} = require('ln-service');
const closing = await closeChannel({id, lnd});
```

### connectWatchtower

Connect to a watchtower

This method requires LND built with `wtclientrpc` build tag

Requires `offchain:write` permission

    {
      lnd: <Authenticated LND>
      public_key: <Watchtower Public Key Hex string>
      socket: <Network Socket Address IP:PORT string>
    }

Example:

```node
const {connectWatchtower, getTowerServerInfo} = require('ln-service');

const {tower} = await getTowerServerInfo({lnd: towerServerLnd});

const socket? = tower.sockets;

await connectWatchtower({lnd, socket, public_key: tower.public_key});
```

### createChainAddress

Create a new receive address.

Requires `address:write` permission

    {
      format: <Receive Address Type string> // "np2wpkh" || "p2wpkh"
      is_unused?: <Get As-Yet Unused Address boolean>
      lnd: <Authenticated LND>
    }

Example:

```node
const {createChainAddress} = require('ln-service');
const format = 'p2wpkh';
const {address} = await createChainAddress({format, lnd});
```

### createHodlInvoice

Create HODL invoice. This invoice will not settle automatically when an
HTLC arrives. It must be settled separately with the secret preimage.

Warning: make sure to cancel the created invoice before its CLTV timeout.

Requires LND built with `invoicesrpc` tag

Requires `address:write`, `invoices:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      description?: <Invoice Description string>
      description_hash?: <Hashed Description of Payment Hex string>
      expires_at?: <Expires At ISO 8601 Date string>
      id?: <Payment Hash Hex string>
      is_fallback_included?: <Is Fallback Address Included boolean>
      is_fallback_nested?: <Is Fallback Address Nested boolean>
      is_including_private_channels?: <Invoice Includes Private Channels boolean>
      lnd: <Authenticated LND>
      mtokens?: <Millitokens string>
      tokens?: <Tokens number>
    }

    @returns via cbk or Promise
    {
      chain_address?: <Backup Address string>
      created_at: <ISO 8601 Date string>
      description: <Description string>
      id: <Payment Hash Hex string>
      mtokens: <Millitokens number>
      request: <BOLT 11 Encoded Payment Request string>
      secret?: <Hex Encoded Payment Secret string>
      tokens: <Tokens number>
    }

Example:

```node
const {createHash, randomBytes} = require('crypto');
const {createHodlInvoice, settleHodlInvoice} = require('ln-service');
const {subscribeToInvoice} = require('ln-service');

const randomSecret = () => randomBytes(32);
const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');

// Choose an r_hash for this invoice, a single sha256, on say randomBytes(32)
const secret = randomSecret();

const id = sha256(secret);

// Supply an authenticatedLndGrpc object for an lnd built with invoicesrpc tag
const {request} = await createHodlInvoice({id, lnd});

// Share the request with the payer and wait for a payment
const sub = subscribeToInvoice({id, lnd});

sub.on('invoice_updated', async invoice => {
  // Only actively held invoices can be settled
  if (!invoice.is_held) {
    return;
  }

  // Use the secret to claim the funds
  await settleHodlInvoice({lnd, secret: secret.toString('hex')});
});
```

### createInvoice

Create a Lightning invoice.

Requires `address:write`, `invoices:write` permission

    {
      cltv_delta?: <CLTV Delta number>
      description?: <Invoice Description string>
      description_hash?: <Hashed Description of Payment Hex string>
      expires_at?: <Expires At ISO 8601 Date string>
      is_fallback_included?: <Is Fallback Address Included boolean>
      is_fallback_nested?: <Is Fallback Address Nested boolean>
      is_including_private_channels?: <Invoice Includes Private Channels boolean>
      lnd: <Authenticated LND>
      secret?: <Payment Preimage Hex string>
      mtokens?: <Millitokens string>
      tokens?: <Tokens number>
    }

    @returns via cbk or Promise
    {
      chain_address?: <Backup Address string>
      created_at: <ISO 8601 Date string>
      description?: <Description string>
      id: <Payment Hash Hex string>
      mtokens?: <Millitokens string>
      request: <BOLT 11 Encoded Payment Request string>
      secret: <Hex Encoded Payment Secret string>
      tokens?: <Tokens number>
    }

Example:

```node
const {createInvoice} = require('ln-service');

// Create a zero value invoice
const invoice = await createInvoice({lnd});
```

### createSeed

Create a wallet seed

Requires unlocked lnd and unauthenticated LND

    {
      lnd: <Unauthenticated LND>
      passphrase?: <Seed Passphrase string>
    }

    @returns via cbk or Promise
    {
      seed: <Cipher Seed Mnemonic string>
    }

Example:

```node
const {createSeed, createWallet} = require('ln-service');
const {seed} = await createSeed({lnd});

// Use the seed to create a wallet
await createWallet({lnd, seed, password: '123456'});
```

### createSignedRequest

Assemble a signed payment request

    {
      destination: <Destination Public Key Hex string>
      hrp: <Request Human Readable Part string>
      signature: <Request Hash Signature Hex string>
      tags: <Request Tag Word number>?
    }

    @throws
    <Error>

    @returns
    {
      request: <BOLT 11 Encoded Payment Request string>
    }

Example:

```node
const {createSignedRequest} = require('ln-service');

// Get hrp and signature from createUnsignedRequest
// Get signature via standard private key signing, or LND signBytes
const {request} = createSignedRequest({
  destination: nodePublicKey,
  hrp: amountAndNetworkHrp,
  signature: signedPreimageHash,
  tags: paymentRequestTags,
});
```

### createUnsignedRequest

Create an unsigned payment request

    {
      chain_addresses]: [<Chain Address string>?
      cltv_delta?: <CLTV Delta number>
      created_at?: <Invoice Creation Date ISO 8601 string>
      description?: <Description string>
      description_hash?: <Description Hash Hex string>
      destination: <Public Key string>
      expires_at?: <ISO 8601 Date string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
      }]
      id: <Preimage SHA256 Hash Hex string>
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
      network: <Network Name string>
      payment?: <Payment Identifier Hex string>
      routes?: [[{
        base_fee_mtokens?: <Base Fee Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <Final CLTV Expiration Blocks Delta number>
        fee_rate?: <Fees Charged in Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens?: <Requested Chain Tokens number> (note: can differ from mtokens)
    }

    @returns
    {
      hash: <Payment Request Signature Hash Hex string>
      hrp: <Human Readable Part of Payment Request string>
      preimage: <Signature Hash Preimage Hex string>
      tags: <Data Tag number>?
    }

Example:

```node
const {createUnsignedRequest} = require('ln-service');

const unsignedComponents = createUnsignedRequest({
  destination: nodePublicKey,
  id: rHashHexString,
  network: 'bitcoin',
});
// Use createSignedRequest and a signature to create a complete request
```

### createWallet

Create a wallet

Requires unlocked lnd and unauthenticated LND

    {
      lnd: <Unauthenticated LND>
      passphrase?: <AEZSeed Encryption Passphrase string>
      password: <Wallet Password string>
      seed: <Seed Mnemonic string>
    }

    @returns via cbk or Promise

Example:

```node
const {createWallet} = require('ln-service');
const {seed} = await createSeed({lnd});
await createWallet({lnd, seed, password: 'password'});
```

### decodePaymentRequest

Get decoded payment request

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
      request: <BOLT 11 Payment Request string>
    }

    @returns via cbk or Promise
    {
      chain_address: <Fallback Chain Address string>
      cltv_delta?: <Final CLTV Delta number>
      description: <Payment Description string>
      description_hash: <Payment Longer Description Hash string>
      destination: <Public Key string>
      expires_at: <ISO 8601 Date string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required To Pay boolean>
        type: <Feature Type string>
      }]
      id: <Payment Hash string>
      mtokens: <Requested Millitokens string>
      payment?: <Payment Identifier Hex Encoded string>
      routes: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      safe_tokens: <Requested Tokens Rounded Up number>
      tokens: <Requested Tokens Rounded Down number>
    }

Example:

```node
const {decodePaymentRequest} = require('ln-service');
const request = 'bolt11EncodedPaymentRequestString';
const details = await decodePaymentRequest({lnd, request});
```

### deleteForwardingReputations

Delete all forwarding reputations

Requires `offchain:write` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {deleteForwardingReputations} = require('ln-service');

// Delete all routing reputations to clear pathfinding memory
await deleteForwardingReputations({});
```

### deletePayments

Delete all records of payments

Requires `offchain:write` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {deletePayments} = require('ln-service');

// Eliminate all the records of past payments
await deletePayments({lnd});
```

### diffieHellmanComputeSecret

Derive a shared secret

Key family and key index default to 6 and 0, which is the node identity key

Requires LND built with `signerrpc` build tag

Requires `signer:generate` permission

    {
      key_family?: <Key Family number>
      key_index?: <Key Index number>
      lnd: <Authenticated LND>
      partner_public_key: <Public Key Hex string>
    }

    @returns via cbk or Promise
    {
      secret: <Shared Secret Hex string>
    }

### disconnectWatchtower

Disconnect a watchtower

Requires LND built with `wtclientrpc` build tag

Requires `offchain:write` permission

    {
      lnd: <Authenticated LND>
      public_key: <Watchtower Public Key Hex string>
    }

    @returns via cbk or Promise

```node
const {disconnectWatchtower, getConnectedWatchtowers} = require('ln-service');

const tower? = (await getConnectedWatchtowers({lnd})).towers;

await disconnectWatchtower({lnd, public_key: tower.public_key});
```

### fundPendingChannels

Fund pending channels

Requires `offchain:write`, `onchain:write` permissions

    {
      channels: <Pending Channel Id Hex string>?
      funding: <Signed Funding Transaction PSBT Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

```node
const {fundPendingChannels, openChannels} = require('ln-service');

const channelsToOpen = {capacity: 1e6, partner_public_key: publicKey}?;

const {pending} = await openChannels({lnd, channel: channelsToOpen});

const channels = pending.map(n => n.id);

// Fund the pending open channels request
await fundPendingChannels({channels, lnd, funding: psbt});
```

### fundPsbt

Lock and optionally select inputs to a partially signed transaction

Specify outputs or PSBT with the outputs encoded

If there are no inputs passed, internal UTXOs will be selected and locked

Requires `onchain:write` permission

Requires LND built with `walletrpc` tag

This method is not supported in LND 0.11.1 and below

    {
      fee_tokens_per_vbyte?: <Chain Fee Tokens Per Virtual Byte number>
      inputs?: [{
        transaction_id: <Unspent Transaction Id Hex string>
        transaction_vout: <Unspent Transaction Output Index number>
      }]
      lnd: <Authenticated LND>
      outputs?: [{
        address: <Chain Address string>
        tokens: <Send Tokens Tokens number>
      }]
      target_confirmations?: <Confirmations To Wait number>
      psbt?: <Existing PSBT Hex string>
    }

    @returns via cbk or Promise
    {
      inputs: [{
        lock_expires_at?: <UTXO Lock Expires At ISO 8601 Date string>
        lock_id?: <UTXO Lock Id Hex string>
        transaction_id: <Unspent Transaction Id Hex string>
        transaction_vout: <Unspent Transaction Output Index number>
      }]
      outputs: [{
        is_change: <Spends To a Generated Change Output boolean>
        output_script: <Output Script Hex string>
        tokens: <Send Tokens Tokens number>
      }]
      psbt: <Unsigned PSBT Hex string>
    }

Example:

```node
const {fundPsbt} = require('ln-service');

const address = 'chainAddress';
const tokens = 1000000;

// Create an unsigned PSBT that sends 1mm to a chain address
const {psbt} = await fundPsbt({lnd, outputs: {address, tokens}?});

// This PSBT can be used with signPsbt to sign and finalize for broadcast
```

### getAccessIds

Get outstanding access ids given out

Note: this method is not supported in LND versions 0.11.1 and below

Requires `macaroon:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      ids: <Root Access Id number>?
    }

Example:

```node
const {getAccessIds, grantAccess} = require('ln-service');

// Create a macaroon that can be used to make off-chain payments
const {macaroon} = await grantAccess({lnd, id: '1', is_ok_to_pay: true});

// Get outstanding ids
const {ids} = await getAccessIds({lnd});

// The specified id '1' will appear in the ids array
```

### getAutopilot

Get Autopilot status

Optionally, get the score of nodes as considered by the autopilot.
Local scores reflect an internal scoring that includes local channel info

Permission `info:read` is required

    {
      lnd: <Authenticated LND>
      node_scores]: [<Get Score For Public Key Hex string>?
    }

    @returns via cbk or Promise
    {
      is_enabled: <Autopilot is Enabled boolean>
      nodes: [{
        local_preferential_score: <Local-adjusted Pref Attachment Score number>
        local_score: <Local-adjusted Externally Set Score number>
        preferential_score: <Preferential Attachment Score number>
        public_key: <Node Public Key Hex string>
        score: <Externally Set Score number>
        weighted_local_score: <Combined Weighted Locally-Adjusted Score number>
        weighted_score: <Combined Weighted Score number>
      }]
    }

Example:

```node
const {getAutopilot} = require('ln-service');
const isAutopilotEnabled = (await getAutopilot({lnd})).is_enabled;
```

### getBackup

Get the static channel backup for a channel

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
      transaction_id: <Funding Transaction Id Hex string>
      transaction_vout: <Funding Transaction Output Index number>
    }

    @returns via cbk or Promise
    {
      backup: <Channel Backup Hex string>
    }

Example:

```node
const {getBackup, getChannels} = require('ln-service');
const channel? = (await getChannels({lnd})).channels;
const {backup} = await getBackup({
  lnd,
  transaction_id: channel.transaction_id,
  transaction_vout: channel.transaction_vout,
});
```

### getBackups

Get all channel backups

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      backup: <All Channels Backup Hex string>
      channels: {
        backup: <Individualized Channel Backup Hex string>
        transaction_id: <Channel Funding Transaction Id Hex string>
        transaction_vout: <Channel Funding Transaction Output Index number>
      }
    }

Example:

```node
const {getBackups} = require('ln-service');
const {backup} = await getBackups({lnd});
```

### getChainBalance

Get balance on the chain.

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      chain_balance: <Confirmed Chain Balance Tokens number>
    }

Example:

```node
const {getChainBalance} = require('ln-service');
const chainBalance = (await getChainBalance({lnd})).chain_balance;
```

### getChainFeeEstimate

Get a chain fee estimate for a prospective chain send

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
      send_to: [{
        address: <Address string>
        tokens: <Tokens number>
      }]
      target_confirmations?: <Target Confirmations number>
    }

    @returns via cbk or Promise
    {
      fee: <Total Fee Tokens number>
      tokens_per_vbyte: <Fee Tokens Per VByte number>
    }

Example:

```node
const {getChainFeeEstimate} = require('ln-service');
const sendTo = {address: 'chainAddressString', tokens: 100000000}?;
const {fee} = await getChainFeeEstimate({lnd, send_to: sendTo});
```

### getChainFeeRate

Get chain fee rate estimate

Requires LND built with `walletrpc` tag

Requires `onchain:read` permission

    {
      confirmation_target?: <Future Blocks Confirmation number>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      tokens_per_vbyte: <Tokens Per Virtual Byte number>
    }

Example:

```node
const {getChainFeeRate} = require('ln-service');
const fee = (await getChainFeeRate({lnd, confirmation_target: 6})).tokens_per_vbyte;
```

### getChainTransactions

Get chain transactions.

Requires `onchain:read` permission

    {
      after?: <Confirmed After Current Best Chain Block Height number>
      before?: <Confirmed Before Current Best Chain Block Height number>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      transactions: [{
        block_id?: <Block Hash string>
        confirmation_count?: <Confirmation Count number>
        confirmation_height?: <Confirmation Block Height number>
        created_at: <Created ISO 8601 Date string>
        description?: <Transaction Label string>
        fee?: <Fees Paid Tokens number>
        id: <Transaction Id string>
        is_confirmed: <Is Confirmed boolean>
        is_outgoing: <Transaction Outbound boolean>
        output_addresses: <Address string>?
        tokens: <Tokens Including Fee number>
        transaction?: <Raw Transaction Hex string>
      }]
    }

Example:

```node
const {getChainTransactions} = require('ln-service');
const {transactions} = await getChainTransactions({lnd});
```

### getChannelBalance

Get balance across channels.

Requires `offchain:read` permission

`channel_balance_mtokens` is not supported on LND 0.11.1 and below

`inbound` and `inbound_mtokens` are not supported on LND 0.11.1 and below

`pending_inbound` is not supported on LND 0.11.1 and below

`unsettled_balance` is not supported on LND 0.11.1 and below

`unsettled_balance_mtokens` is not supported on LND 0.11.1 and below

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      channel_balance: <Channels Balance Tokens number>
      channel_balance_mtokens?: <Channels Balance Millitokens string>
      inbound?: <Inbound Liquidity Tokens number>
      inbound_mtokens?: <Inbound Liquidity Millitokens string>
      pending_balance: <Pending On-Chain Channels Balance Tokens number>
      pending_inbound?: <Pending On-Chain Inbound Liquidity Tokens number>
      unsettled_balance?: <In-Flight Tokens number>
      unsettled_balance_mtokens?: <In-Flight Millitokens number>
    }

Example:

```node
const {getChannelBalance} = require('ln-service');
const balanceInChannels = (await getChannelBalance({lnd})).channel_balance;
```

### getChannel

Get graph information about a channel on the network

Requires `info:read` permission

    {
      id: <Standard Format Channel Id string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      capacity: <Maximum Tokens number>
      id: <Standard Format Channel Id string>
      policies: [{
        base_fee_mtokens?: <Base Fee Millitokens string>
        cltv_delta?: <Locktime Delta number>
        fee_rate?: <Fees Charged Per Million Millitokens number>
        is_disabled?: <Channel Is Disabled boolean>
        max_htlc_mtokens?: <Maximum HTLC Millitokens Value string>
        min_htlc_mtokens?: <Minimum HTLC Millitokens Value string>
        public_key: <Node Public Key string>
        updated_at?: <Policy Last Updated At ISO 8601 Date string>
      }]
      transaction_id: <Transaction Id Hex string>
      transaction_vout: <Transaction Output Index number>
      updated_at?: <Last Update Epoch ISO 8601 Date string>
    }

Example:

```node
const {getChannel} = await require('ln-service');
const id = '0x0x0';
const channelDetails = await getChannel({id, lnd});
```

### getChannels

Get channels

Requires `offchain:read` permission

`in_channel`, `in_payment`, `is_forward`, `out_channel`, `out_payment`,
`payment` are not supported on LND 0.11.1 and below

    {
      is_active?: <Limit Results To Only Active Channels boolean> // false
      is_offline?: <Limit Results To Only Offline Channels boolean> // false
      is_private?: <Limit Results To Only Private Channels boolean> // false
      is_public?: <Limit Results To Only Public Channels boolean> // false
      lnd: <Authenticated LND>
      partner_public_key?: <Only Channels With Public Key Hex string>
    }

    @returns via cbk or Promise
    {
      channels: [{
        capacity: <Channel Token Capacity number>
        commit_transaction_fee: <Commit Transaction Fee number>
        commit_transaction_weight: <Commit Transaction Weight number>
        cooperative_close_address?: <Coop Close Restricted to Address string>
        cooperative_close_delay_height?: <Prevent Coop Close Until Height number>
        id: <Standard Format Channel Id string>
        is_active: <Channel Active boolean>
        is_closing: <Channel Is Closing boolean>
        is_opening: <Channel Is Opening boolean>
        is_partner_initiated: <Channel Partner Opened Channel boolean>
        is_private: <Channel Is Private boolean>
        is_static_remote_key: <Remote Key Is Static boolean>
        local_balance: <Local Balance Tokens number>
        local_csv?: <Local CSV Blocks Delay number>
        local_dust?: <Remote Non-Enforceable Amount Tokens number>
        local_given?: <Local Initially Pushed Tokens number>
        local_max_htlcs?: <Local Maximum Attached HTLCs number>
        local_max_pending_mtokens?: <Local Maximum Pending Millitokens string>
        local_min_htlc_mtokens?: <Local Minimum HTLC Millitokens string>
        local_reserve: <Local Reserved Tokens number>
        partner_public_key: <Channel Partner Public Key string>
        pending_payments: [{
          id: <Payment Preimage Hash Hex string>
          in_channel?: <Forward Inbound From Channel Id string>
          in_payment?: <Payment Index on Inbound Channel number>
          is_forward?: <Payment is a Forward boolean>
          is_outgoing: <Payment Is Outgoing boolean>
          out_channel?: <Forward Outbound To Channel Id string>
          out_payment?: <Payment Index on Outbound Channel number>
          payment?: <Payment Attempt Id number>
          timeout: <Chain Height Expiration number>
          tokens: <Payment Tokens number>
        }]
        received: <Received Tokens number>
        remote_balance: <Remote Balance Tokens number>
        remote_csv?: <Remote CSV Blocks Delay number>
        remote_dust?: <Remote Non-Enforceable Amount Tokens number>
        remote_given?: <Remote Initially Pushed Tokens number>
        remote_max_htlcs?: <Remote Maximum Attached HTLCs number>
        remote_max_pending_mtokens?: <Remote Maximum Pending Millitokens string>
        remote_min_htlc_mtokens?: <Remote Minimum HTLC Millitokens string>
        remote_reserve: <Remote Reserved Tokens number>
        sent: <Sent Tokens number>
        time_offline?: <Monitoring Uptime Channel Down Milliseconds number>
        time_online?: <Monitoring Uptime Channel Up Milliseconds number>
        transaction_id: <Blockchain Transaction Id string>
        transaction_vout: <Blockchain Transaction Vout number>
        unsettled_balance: <Unsettled Balance Tokens number>
      }]
    }

Example:

```node
const {getChannels} = require('ln-service');

// Get the channels and count how many there are
const channelsCount = (await getChannels({lnd})).length;
```

### getClosedChannels

Get closed out channels

Multiple close type flags are supported.

Requires `offchain:read` permission

    {
      is_breach_close?: <Only Return Breach Close Channels boolean>
      is_cooperative_close?: <Only Return Cooperative Close Channels boolean>
      is_funding_cancel?: <Only Return Funding Canceled Channels boolean>
      is_local_force_close?: <Only Return Local Force Close Channels boolean>
      is_remote_force_close?: <Only Return Remote Force Close Channels boolean>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      channels: [{
        capacity: <Closed Channel Capacity Tokens number>
        close_balance_spent_by?: <Channel Balance Output Spent By Tx Id string>
        close_balance_vout?: <Channel Balance Close Tx Output Index number>
        close_payments: [{
          is_outgoing: <Payment Is Outgoing boolean>
          is_paid: <Payment Is Claimed With Preimage boolean>
          is_pending: <Payment Resolution Is Pending boolean>
          is_refunded: <Payment Timed Out And Went Back To Payer boolean>
          spent_by?: <Close Transaction Spent By Transaction Id Hex string>
          tokens: <Associated Tokens number>
          transaction_id: <Transaction Id Hex string>
          transaction_vout: <Transaction Output Index number>
        }]
        close_confirm_height?: <Channel Close Confirmation Height number>
        close_transaction_id?: <Closing Transaction Id Hex string>
        final_local_balance: <Channel Close Final Local Balance Tokens number>
        final_time_locked_balance: <Closed Channel Timelocked Tokens number>
        id?: <Closed Standard Format Channel Id string>
        is_breach_close: <Is Breach Close boolean>
        is_cooperative_close: <Is Cooperative Close boolean>
        is_funding_cancel: <Is Funding Cancelled Close boolean>
        is_local_force_close: <Is Local Force Close boolean>
        is_partner_closed?: <Channel Was Closed By Channel Peer boolean>
        is_partner_initiated?: <Channel Was Initiated By Channel Peer boolean>
        is_remote_force_close: <Is Remote Force Close boolean>
        partner_public_key: <Partner Public Key Hex string>
        transaction_id: <Channel Funding Transaction Id Hex string>
        transaction_vout: <Channel Funding Output Index number>
      }]
    }

Example:

```node
const {getClosedChannels} = require('ln-service');
const breachCount = await getClosedChannels({lnd, is_breach_close: true});
```

### getConnectedWatchtowers

Get a list of connected watchtowers and watchtower info

Requires LND built with `wtclientrpc` build tag

Requires `offchain:read` permission

Includes previously connected watchtowers

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      max_session_update_count: <Maximum Updates Per Session number>
      sweep_tokens_per_vbyte: <Sweep Tokens per Virtual Byte number>
      backups_count: <Total Backups Made Count number>
      failed_backups_count: <Total Backup Failures Count number>
      finished_sessions_count: <Finished Updated Sessions Count number>
      pending_backups_count: <As Yet Unacknowledged Backup Requests Count number>
      sessions_count: <Total Backup Sessions Starts Count number>
      towers: [{
        is_active: <Tower Can Be Used For New Sessions boolean>
        public_key: <Identity Public Key Hex string>
        sessions: [{
          backups_count: <Total Successful Backups Made Count number>
          max_backups_count: <Backups Limit number>
          pending_backups_count: <Backups Pending Acknowledgement Count number>
          sweep_tokens_per_vbyte: <Fee Rate in Tokens Per Virtual Byte number>
        }]
        sockets: <Tower Network Address IP:Port string>?
      }]
    }

Example:

```node
const {getConnectedWatchtowers} = require('ln-service');

const {towers} = (await getConnectedWatchtowers({lnd}));
```

### getFeeRates

Get a rundown on fees for channels

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      channels: [{
        base_fee: <Base Flat Fee Tokens Rounded Up number>
        base_fee_mtokens: <Base Flat Fee Millitokens string>
        id: <Standard Format Channel Id string>
        transaction_id: <Channel Funding Transaction Id Hex string>
        transaction_vout: <Funding Outpoint Output Index number>
      }]
    }

Example:

```node
const {getFeeRates} = require('ln-service');
const {channels} = await getFeeRates({lnd});
```

### getForwardingConfidence

Get the confidence in being able to send between a direct pair of nodes

    {
      from: <From Public Key Hex string>
      lnd: <Authenticated LND>
      mtokens: <Millitokens To Send string>
      to: <To Public Key Hex string>
    }

    @returns via cbk or Promise
    {
      confidence: <Success Confidence Score Out Of One Million number>
    }

Example:

```node
const {getForwardingConfidence} = require('ln-service');
const from = nodeAPublicKey;
const mtokens = '10000';
const to = nodeBPublicKey;

// Given two nodes, get confidence score out of 1,000,000 in forwarding success
const {confidence} = await getForwardingConfidence({from, lnd, mtokens, to});
```

### getForwardingReputations

Get the set of forwarding reputations

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      nodes: [{
        peers: [{
          failed_tokens?: <Failed to Forward Tokens number>
          forwarded_tokens?: <Forwarded Tokens number>
          last_failed_forward_at?: <Failed Forward At ISO-8601 Date string>
          last_forward_at?: <Forwarded At ISO 8601 Date string>
          to_public_key: <To Public Key Hex string>
        }]
        public_key: <Node Identity Public Key Hex string>
      }]
    }

```node
const {getForwardingReputations} = require('ln-service');
const {nodes} = await getForwardingReputations({lnd});
```

### getForwards

Get forwarded payments, from oldest to newest

When using an "after" date a "before" date is required.

If a next token is returned, pass it to get additional page of results.

Requires `offchain:read` permission

    {
      after?: <Get Only Payments Forwarded At Or After ISO 8601 Date string>
      before?: <Get Only Payments Forwarded Before ISO 8601 Date string>
      limit?: <Page Result Limit number>
      lnd: <Authenticated LND>
      token?: <Opaque Paging Token string>
    }

    @returns via cbk or Promise
    {
      forwards: [{
        created_at: <Forward Record Created At ISO 8601 Date string>
        fee: <Fee Tokens Charged number>
        fee_mtokens: <Approximated Fee Millitokens Charged string>
        incoming_channel: <Incoming Standard Format Channel Id string>
        mtokens: <Forwarded Millitokens string>
        outgoing_channel: <Outgoing Standard Format Channel Id string>
        tokens: <Forwarded Tokens number>
      }]
      next?: <Contine With Opaque Paging Token string>
    }

Example:

```node
const {getForwards} = require('ln-service');
const {forwards} = await getForwards({lnd});
```

### getHeight

Lookup the current best block height

LND with `chainrpc` build tag and `onchain:read` permission is suggested

Otherwise, `info:read` permission is required

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      current_block_hash: <Best Chain Hash Hex string>
      current_block_height: <Best Chain Height number>
    }

Example:

```node
const {getHeight} = require('ln-service');

// Check for the current best chain block height
const height = (await getHeight({lnd})).current_block_height;
```

### getIdentity

Lookup the identity key for a node

LND with `walletrpc` build tag and `address:read` permission is suggested

Otherwise, `info:read` permission is required

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      public_key: <Node Identity Public Key Hex string>
    }

Example:

```node
const {getIdentity} = require('ln-service');

// Derive the identity public key of the backing LND node
const nodePublicKey = (await getIdentity({lnd})).public_key;
```

### getInvoice

Lookup a channel invoice.

The received value and the invoiced value may differ as invoices may be
over-paid.

Requires `invoices:read` permission

    {
      id: <Payment Hash Id Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      chain_address?: <Fallback Chain Address string>
      cltv_delta: <CLTV Delta number>
      confirmed_at?: <Settled at ISO 8601 Date string>
      created_at: <ISO 8601 Date string>
      description: <Description string>
      description_hash?: <Description Hash Hex string>
      expires_at: <ISO 8601 Date string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required To Pay boolean>
        type: <Feature Type string>
      }]
      id: <Payment Hash string>
      is_canceled?: <Invoice is Canceled boolean>
      is_confirmed: <Invoice is Confirmed boolean>
      is_held?: <HTLC is Held boolean>
      is_private: <Invoice is Private boolean>
      is_push?: <Invoice is Push Payment boolean>
      payments: [{
        confirmed_at?: <Payment Settled At ISO 8601 Date string>
        created_at: <Payment Held Since ISO 860 Date string>
        created_height: <Payment Held Since Block Height number>
        in_channel: <Incoming Payment Through Channel Id string>
        is_canceled: <Payment is Canceled boolean>
        is_confirmed: <Payment is Confirmed boolean>
        is_held: <Payment is Held boolean>
        messages: [{
          type: <Message Type number string>
          value: <Raw Value Hex string>
        }]
        mtokens: <Incoming Payment Millitokens string>
        pending_index?: <Pending Payment Channel HTLC Index number>
        tokens: <Payment Tokens number>
      }]
      received: <Received Tokens number>
      received_mtokens: <Received Millitokens string>
      request?: <Bolt 11 Invoice string>
      secret: <Secret Preimage Hex string>
      tokens: <Tokens number>
    }

Example:

```node
const {getInvoice} = require('ln-service');
const invoiceDetails = await getInvoice({id, lnd});
```

### getInvoices

Get all created invoices.

If a next token is returned, pass it to get another page of invoices.

Requires `invoices:read` permission

    {
      limit?: <Page Result Limit number>
      lnd: <Authenticated LND>
      token?: <Opaque Paging Token string>
    }

    @returns via cbk or Promise
    {
      invoices: [{
        chain_address?: <Fallback Chain Address string>
        confirmed_at?: <Settled at ISO 8601 Date string>
        created_at: <ISO 8601 Date string>
        description: <Description string>
        description_hash?: <Description Hash Hex string>
        expires_at: <ISO 8601 Date string>
        features: [{
          bit: <BOLT 09 Feature Bit number>
          is_known: <Feature is Known boolean>
          is_required: <Feature Support is Required To Pay boolean>
          type: <Feature Type string>
        }]
        id: <Payment Hash string>
        is_canceled?: <Invoice is Canceled boolean>
        is_confirmed: <Invoice is Confirmed boolean>
        is_held?: <HTLC is Held boolean>
        is_private: <Invoice is Private boolean>
        is_push?: <Invoice is Push Payment boolean>
        payments: [{
          confirmed_at?: <Payment Settled At ISO 8601 Date string>
          created_at: <Payment Held Since ISO 860 Date string>
          created_height: <Payment Held Since Block Height number>
          in_channel: <Incoming Payment Through Channel Id string>
          is_canceled: <Payment is Canceled boolean>
          is_confirmed: <Payment is Confirmed boolean>
          is_held: <Payment is Held boolean>
          messages: [{
            type: <Message Type number string>
            value: <Raw Value Hex string>
          }]
          mtokens: <Incoming Payment Millitokens string>
          pending_index?: <Pending Payment Channel HTLC Index number>
          tokens: <Payment Tokens number>
          total_mtokens?: <Total Millitokens string>
        }]
        received: <Received Tokens number>
        received_mtokens: <Received Millitokens string>
        request?: <Bolt 11 Invoice string>
        secret: <Secret Preimage Hex string>
        tokens: <Tokens number>
      }]
      next?: <Next Opaque Paging Token string>
    }

Example:

```node
const {getInvoices} = require('ln-service');
const {invoices} = await getInvoices({lnd});
```

### getMethods

Get the list of all methods and their associated requisite permissions

Note: this method is not supported in LND versions 0.11.1 and below

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      methods: [{
        endpoint: <Method Endpoint Path string>
        permissions: <Entity:Action string>]
      }]
    }

Example:

```node
const {getMethods} = require('ln-service');
const perrmissions = 'info:read'?;

const {methods} = await getMethods({lnd});

// Calculate allowed methods for permissions set
const allowedMethods = methods.filter(method => {
  // A method is allowed if all of its permissions are included
  return !method.permissions.find(n => !permissions.includes(n));
});
```

### getNetworkCentrality

Get the graph centrality scores of the nodes on the network

Scores are from 0 to 1,000,000.

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      nodes: [{
        betweenness: <Betweenness Centrality number>
        betweenness_normalized: <Normalized Betweenness Centrality number>
        public_key: <Node Public Key Hex string>
      }]
    }

```node
const {getNetworkCentrality} = require('ln-service');

// Calculate centrality scores for all graph nodes
const centrality = await getNetworkCentrality({lnd});
```

### getNetworkGraph

Get the network graph

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      channels: [{
        capacity: <Channel Capacity Tokens number>
        id: <Standard Format Channel Id string>
        policies: [{
          base_fee_mtokens?: <Bae Fee Millitokens string>
          cltv_delta?: <CLTV Height Delta number>
          fee_rate?: <Fee Rate In Millitokens Per Million number>
          is_disabled?: <Edge is Disabled boolean>
          max_htlc_mtokens?: <Maximum HTLC Millitokens string>
          min_htlc_mtokens?: <Minimum HTLC Millitokens string>
          public_key: <Public Key string>
          updated_at?: <Last Update Epoch ISO 8601 Date string>
        }]
        transaction_id: <Funding Transaction Id string>
        transaction_vout: <Funding Transaction Output Index number>
        updated_at?: <Last Update Epoch ISO 8601 Date string>
      }]
      nodes: [{
        alias: <Name string>
        color: <Hex Encoded Color string>
        features: [{
          bit: <BOLT 09 Feature Bit number>
          is_known: <Feature is Known boolean>
          is_required: <Feature Support is Required boolean>
          type: <Feature Type string>
        }]
        public_key: <Node Public Key string>
        sockets: <Network Address and Port string>?
        updated_at: <Last Updated ISO 8601 Date string>
      }]
    }

Example:

```node
const {getNetworkGraph} = require('ln-service');
const {channels, nodes} = await getNetworkGraph({lnd});
```

### getNetworkInfo

Get network info

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      average_channel_size: <Tokens number>
      channel_count: <Channels Count number>
      max_channel_size: <Tokens number>
      median_channel_size: <Median Channel Tokens number>
      min_channel_size: <Tokens number>
      node_count: <Node Count number>
      not_recently_updated_policy_count: <Channel Edge Count number>
      total_capacity: <Total Capacity number>
    }

Example:

```node
const {getNetworkInfo} = require('ln-service');
const {networkDetails} = await getNetworkInfo({lnd});
```

### getNode

Get information about a node

Requires `info:read` permission

    {
      is_omitting_channels?: <Omit Channels from Node boolean>
      lnd: <Authenticated LND>
      public_key: <Node Public Key Hex string>
    }

    @returns via cbk or Promise
    {
      alias: <Node Alias string>
      capacity: <Node Total Capacity Tokens number>
      channel_count: <Known Node Channels number>
      channels?: [{
        capacity: <Maximum Tokens number>
        id: <Standard Format Channel Id string>
        policies: [{
          base_fee_mtokens?: <Base Fee Millitokens string>
          cltv_delta?: <Locktime Delta number>
          fee_rate?: <Fees Charged Per Million Millitokens number>
          is_disabled?: <Channel Is Disabled boolean>
          max_htlc_mtokens?: <Maximum HTLC Millitokens Value string>
          min_htlc_mtokens?: <Minimum HTLC Millitokens Value string>
          public_key: <Node Public Key string>
          updated_at?: <Policy Last Updated At ISO 8601 Date string>
        }]
        transaction_id: <Transaction Id Hex string>
        transaction_vout: <Transaction Output Index number>
        updated_at?: <Channel Last Updated At ISO 8601 Date string>
      }]
      color: <RGB Hex Color string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required boolean>
        type: <Feature Type string>
      }]
      sockets: [{
        socket: <Host and Port string>
        type: <Socket Type string>
      }]
      updated_at?: <Last Known Update ISO 8601 Date string>
    }

Example:

```node
const {getNode} = require('ln-service');
const publicKey = 'publicKeyHexString';
const nodeDetails = await getNode({lnd, public_key: publicKey});
```

### getPayment

Get the status of a past payment

Requires `offchain:read` permission

    {
      id: <Payment Preimage Hash Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      failed?: {
        is_insufficient_balance: <Failed Due To Lack of Balance boolean>
        is_invalid_payment: <Failed Due to Payment Rejected At Destination boolean>
        is_pathfinding_timeout: <Failed Due to Pathfinding Timeout boolean>
        is_route_not_found: <Failed Due to Absence of Path Through Graph boolean>
      }
      is_confirmed?: <Payment Is Settled boolean>
      is_failed?: <Payment Is Failed boolean>
      is_pending?: <Payment Is Pending boolean>
      payment?: {
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Routing Fee Tokens number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forwarded Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        id: <Payment Hash Hex string>
        mtokens: <Total Millitokens Paid string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Tokens Rounded Up number>
        secret: <Payment Preimage Hex string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens Paid number>
      }
    }

Example:

```node
const {getPayment} = require('ln-service');
const id = 'paymentHashHexString';
const payment = await getPayment({id, lnd});
```

### getPayments

Get payments made through channels.

Requires `offchain:read` permission

    {
      limit?: <Page Result Limit number>
      lnd: <Authenticated LND>
      token?: <Opaque Paging Token string>
    }

    @returns via cbk or Promise
    {
      payments: [{
        attempts: [{
          failure?: {
            code: <Error Type Code number>
            details?: {
              channel?: <Standard Format Channel Id string>
              height?: <Error Associated Block Height number>
              index?: <Failed Hop Index number>
              mtokens?: <Error Millitokens string>
              policy?: {
                base_fee_mtokens: <Base Fee Millitokens string>
                cltv_delta: <Locktime Delta number>
                fee_rate: <Fees Charged Per Million Tokens number>
                is_disabled?: <Channel is Disabled boolean>
                max_htlc_mtokens: <Maximum HLTC Millitokens Value string>
                min_htlc_mtokens: <Minimum HTLC Millitokens Value string>
                updated_at: <Updated At ISO 8601 Date string>
              }
              timeout_height?: <Error CLTV Timeout Height number>
              update?: {
                chain: <Chain Id Hex string>
                channel_flags: <Channel Flags number>
                extra_opaque_data: <Extra Opaque Data Hex string>
                message_flags: <Message Flags number>
                signature: <Channel Update Signature Hex string>
              }
            }
            message: <Error Message string>
          }
          is_confirmed: <Payment Attempt Succeeded boolean>
          is_failed: <Payment Attempt Failed boolean>
          is_pending: <Payment Attempt is Waiting For Resolution boolean>
          route: {
            fee: <Route Fee Tokens number>
            fee_mtokens: <Route Fee Millitokens string>
            hops: [{
              channel: <Standard Format Channel Id string>
              channel_capacity: <Channel Capacity Tokens number>
              fee: <Fee number>
              fee_mtokens: <Fee Millitokens string>
              forward: <Forward Tokens number>
              forward_mtokens: <Forward Millitokens string>
              public_key?: <Forward Edge Public Key Hex string>
              timeout?: <Timeout Block Height number>
            }]
            mtokens: <Total Fee-Inclusive Millitokens string>
            payment?: <Payment Identifier Hex string>
            timeout: <Timeout Block Height number>
            tokens: <Total Fee-Inclusive Tokens number>
            total_mtokens?: <Total Millitokens string>
          }
        }]
        created_at: <Payment at ISO-8601 Date string>
        destination: <Destination Node Public Key Hex string>
        fee: <Paid Routing Fee Rounded Down Tokens number>
        fee_mtokens: <Paid Routing Fee in Millitokens string>
        hops: <First Route Hop Public Key Hex string>?
        id: <Payment Preimage Hash string>
        index?: <Payment Add Index number>
        is_confirmed: <Payment is Confirmed boolean>
        is_outgoing: <Transaction Is Outgoing boolean>
        mtokens: <Millitokens Sent to Destination string>
        request?: <BOLT 11 Payment Request string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Tokens Rounded Up number>
        secret: <Payment Preimage Hex string>
        tokens: <Rounded Down Tokens Sent to Destination number>
      }]
      next?: <Next Opaque Paging Token string>
    }

Example:

```node
const {getPayments} = require('ln-service');
const {payments} = await getPayments({lnd});
```

### getPeers

Get connected peers.

Requires `peers:read` permission

LND 0.11.1 and below do not return `last_reconnected` or `reconnection_rate`

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      peers: [{
        bytes_received: <Bytes Received number>
        bytes_sent: <Bytes Sent number>
        features: [{
          bit: <BOLT 09 Feature Bit number>
          is_known: <Feature is Known boolean>
          is_required: <Feature Support is Required boolean>
          type: <Feature Type string>
        }]
        is_inbound: <Is Inbound Peer boolean>
        is_sync_peer?: <Is Syncing Graph Data boolean>
        last_reconnected?: <Peer Last Reconnected At ISO 8601 Date string>
        ping_time: <Ping Latency Milliseconds number>
        public_key: <Node Identity Public Key string>
        reconnection_rate?: <Count of Reconnections Over Time number>
        socket: <Network Address And Port string>
        tokens_received: <Amount Received Tokens number>
        tokens_sent: <Amount Sent Tokens number>
      }]
    }

Example:

```node
const {getPeers} = require('ln-service');
const {peers} = await getPeers({lnd});
```

### getPendingChainBalance

Get pending chain balance in simple unconfirmed outputs.

Pending channels limbo balance is not included

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      pending_chain_balance: <Pending Chain Balance Tokens number>
    }

Example:

```node
const {getPendingChainBalance} = require('ln-service');
const totalPending = (await getPendingChainBalance({lnd})).pending_chain_balance;
```

### getPendingChannels

Get pending channels.

Both `is_closing` and `is_opening` are returned as part of a channel because a
channel may be opening, closing, or active.

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      pending_channels: [{
        close_transaction_id?: <Channel Closing Transaction Id string>
        is_active: <Channel Is Active boolean>
        is_closing: <Channel Is Closing boolean>
        is_opening: <Channel Is Opening boolean>
        is_partner_initiated?: <Channel Partner Initiated Channel boolean>
        local_balance: <Channel Local Tokens Balance number>
        local_reserve: <Channel Local Reserved Tokens number>
        partner_public_key: <Channel Peer Public Key string>
        pending_balance?: <Tokens Pending Recovery number>
        pending_payments?: [{
          is_incoming: <Payment Is Incoming boolean>
          timelock_height: <Payment Timelocked Until Height number>
          tokens: <Payment Tokens number>
          transaction_id: <Payment Transaction Id string>
          transaction_vout: <Payment Transaction Vout number>
        }]
        received: <Tokens Received number>
        recovered_tokens?: <Tokens Recovered From Close number>
        remote_balance: <Remote Tokens Balance number>
        remote_reserve: <Channel Remote Reserved Tokens number>
        sent: <Send Tokens number>
        timelock_expiration?: <Pending Tokens Block Height Timelock number>
        transaction_fee?: <Funding Transaction Fee Tokens number>
        transaction_id: <Channel Funding Transaction Id string>
        transaction_vout: <Channel Funding Transaction Vout number>
        transaction_weight?: <Funding Transaction Weight number>
      }]
    }

Example:

```node
const {getPendingChannels} = require('ln-service');
const pendingChannels = (await getPendingChannels({lnd})).pending_channels;
```

### getPublicKey

Get a public key in the seed

Omit a key index to cycle to the "next" key in the family

Requires LND compiled with `walletrpc` build tag

Requires `address:read` permission

    {
      family: <Key Family number>
      index?: <Key Index number>
      lnd: <Authenticated API LND>
    }

    @returns via cbk or Promise
    {
      index: <Key Index number>
      public_key: <Public Key Hex string>
    }

Example:

```node
const {getPublicKey} = require('ln-service');

// Get the public version of a key in the LND wallet HD seed
const publicKey = (await getPublicKey({family: 1, index: 1, lnd}).public_key);
```

### getRouteConfidence

Get routing confidence of successfully routing a payment to a destination

If `from` is not set, self is default

Requires `offchain:read` permission

    {
      from?: <Starting Hex Serialized Public Key>
      hops: [{
        forward_mtokens: <Forward Millitokens string>
        public_key: <Forward Edge Public Key Hex string>
      }]
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      confidence: <Confidence Score Out Of One Million number>
    }

Example:

```node
const {getRouteConfidence, getRouteToDestination} = require('ln-service');
const destination = 'destinationPublicKeyHexString';

const {route} = await getRouteToDestination({destination, lnd, tokens: 80085});

// Confidence in payment success
const {confidence} = (await getRouteConfidence({lnd, hops: route.hops}));
```

### getRouteThroughHops

Get an outbound route that goes through specific hops

Requires `offchain:read` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      lnd: <Authenticated LND>
      mtokens?: <Millitokens to Send string>
      outgoing_channel?: <Outgoing Channel Id string>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      payment?: <Payment Identifier Hex string>
      public_keys: <Public Key Hex string>?
      tokens?: <Tokens to Send number>
      total_mtokens?: <Payment Total Millitokens string>
    }

    @returns via cbk or Promise
    {
      route: {
        fee: <Route Fee Tokens number>
        fee_mtokens: <Route Fee Millitokens string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Forward Edge Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
        payment?: <Payment Identifier Hex string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Tokens Rounded Up number>
        timeout: <Route Timeout Height number>
        tokens: <Total Fee-Inclusive Tokens number>
        total_mtokens?: <Payment Total Millitokens string>
      }
    }

Example:

```node
const {getRouteThroughHops, payViaRoutes} = require('ln-service');
const destination = 'destinationPublicKeyHexString';
const mtokens = '1000';
const peer = 'peerPublicKeyHexString';
const {route} = await getRouteThroughHops({lnd, public_keys: peer, destination?});
await payViaRoutes({lnd, routes: route?});
```

### getRouteToDestination

Get a route to a destination.

Call this iteratively after failed route attempts to get new routes

Requires `info:read` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Final Send Destination Hex Encoded Public Key string>
      features?: [{
        bit: <Feature Bit number>
      }]
      ignore?: [{
        channel?: <Channel Id string>
        from_public_key: <Public Key Hex string>
        to_public_key?: <To Public Key Hex string>
      }]
      incoming_peer?: <Incoming Peer Public Key Hex string>
      is_ignoring_past_failures?: <Ignore Past Failures boolean>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens number>
      max_fee_mtokens?: <Maximum Fee Millitokens string>
      max_timeout_height?: <Max CLTV Timeout number>
      messages?: [{
        type: <Message To Final Destination Type number string>
        value: <Message To Final Destination Raw Value Hex Encoded string>
      }]
      mtokens?: <Tokens to Send string>
      outgoing_channel?: <Outgoing Channel Id string>
      payment?: <Payment Identifier Hex Strimng>
      routes?: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens string>
        channel?: <Standard Format Channel Id string>
        channel_capacity?: <Channel Capacity Tokens number>
        cltv_delta?: <CLTV Delta Blocks number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      start?: <Starting Node Public Key Hex string>
      tokens?: <Tokens number>
      total_mtokens?: <Total Millitokens of Shards string>
    }

    @returns via cbk or Promise
    {
      route?: {
        confidence?: <Route Confidence Score Out Of One Million number>
        fee: <Route Fee Tokens number>
        fee_mtokens: <Route Fee Millitokens string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Forward Edge Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Tokens Rounded Up number>
        timeout: <Route Timeout Height number>
        tokens: <Total Fee-Inclusive Tokens number>
      }
    }

Example:

```node
const {getRouteToDestination, payViaRoutes} = require('ln-service');
const destination = 'destinationPublicKeyHexString';
const tokens = 1000;
const {route} = await getRouteToDestination({destination, lnd, tokens});
await payViaRoutes({lnd, routes: route?});
```

### getSweepTransactions

Get self-transfer spend transactions related to channel closes

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      transactions: [{
        block_id?: <Block Hash string>
        confirmation_count?: <Confirmation Count number>
        confirmation_height?: <Confirmation Block Height number>
        created_at: <Created ISO 8601 Date string>
        fee?: <Fees Paid Tokens number>
        id: <Transaction Id string>
        is_confirmed: <Is Confirmed boolean>
        is_outgoing: <Transaction Outbound boolean>
        output_addresses: <Address string>?
        spends: [{
          tokens?: <Output Tokens number>
          transaction_id: <Spend Transaction Id Hex string>
          transaction_vout: <Spend Transaction Output Index number>
        }]
        tokens: <Tokens Including Fee number>
        transaction?: <Raw Transaction Hex string>
      }]
    }

Example:

```node
const {getSweepTransactions} = require('ln-service');

const {transactions} = await getSweepTransactions({lnd});
```

### getTowerServerInfo

Get watchtower server info.

This method requires LND built with `watchtowerrpc` build tag

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      tower?: {
        public_key: <Watchtower Server Public Key Hex string>
        sockets: <Socket string>?
        uris: <Watchtower External URI string>?
      }
    }

Example:

```node
const {getTowerServerInfo} = require('ln-service');
const towerInfo = await getTowerServerInfo({lnd});
```

### getUtxos

Get unspent transaction outputs

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
      max_confirmations?: <Maximum Confirmations number>
      min_confirmations?: <Minimum Confirmations number>
    }

    @returns via cbk or Promise
    {
      utxos: [{
        address: <Chain Address string>
        address_format: <Chain Address Format string>
        confirmation_count: <Confirmation Count number>
        output_script: <Output Script Hex string>
        tokens: <Unspent Tokens number>
        transaction_id: <Transaction Id Hex string>
        transaction_vout: <Transaction Output Index number>
      }]
    }

Example:

```node
const {getUtxos} = require('ln-service');
const {utxos} = await getUtxos({lnd});
```

### getWalletInfo

Get overall wallet info.

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      active_channels_count: <Active Channels Count number>
      alias: <Node Alias string>
      chains: <Chain Id Hex string>?
      color: <Node Color string>
      current_block_hash: <Best Chain Hash Hex string>
      current_block_height: <Best Chain Height number>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required boolean>
        type: <Feature Type string>
      }]
      is_synced_to_chain: <Is Synced To Chain boolean>
      latest_block_at: <Latest Known Block At Date string>
      peers_count: <Peer Count number>
      pending_channels_count: <Pending Channels Count number>
      public_key: <Public Key string>
    }

Example:

```node
const {getWalletInfo} = require('ln-service');
const walletInfo = await getWalletInfo({lnd});
```

### getWalletVersion

Get wallet version

Tags are self-reported by LND and are not guaranteed to be accurate

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      build_tags: <Build Tag string>?
      commit_hash: <Commit SHA1 160 Bit Hash Hex string>
      is_autopilotrpc_enabled: <Is Autopilot RPC Enabled boolean>
      is_chainrpc_enabled: <Is Chain RPC Enabled boolean>
      is_invoicesrpc_enabled: <Is Invoices RPC Enabled boolean>
      is_signrpc_enabled: <Is Sign RPC Enabled boolean>
      is_walletrpc_enabled: <Is Wallet RPC Enabled boolean>
      is_watchtowerrpc_enabled: <Is Watchtower Server RPC Enabled boolean>
      is_wtclientrpc_enabled: <Is Watchtower Client RPC Enabled boolean>
      version?: <Recognized LND Version string>
    }

```node
const {getWalletVersion} = require('ln-service');

// Determine if the invoices rpc build tag was used with the running LND
const hasInvoicesRpc = (await getWalletVersion({lnd})).is_invoicesrpc_enabled;
```

### grantAccess

Give access to the node by making a macaroon access credential

Specify `id` to allow for revoking future access

Requires `macaroon:generate` permission

Note: access once given cannot be revoked. Access is defined at the LND level
and version differences in LND can result in expanded access.

Note: `id` is not supported in LND versions 0.11.0 and below

    {
      id?: <Macaroon Id Positive Numeric string>
      is_ok_to_adjust_peers?: <Can Add or Remove Peers boolean>
      is_ok_to_create_chain_addresses?: <Can Make New Addresses boolean>
      is_ok_to_create_invoices?: <Can Create Lightning Invoices boolean>
      is_ok_to_create_macaroons?: <Can Create Macaroons boolean>
      is_ok_to_derive_keys?: <Can Derive Public Keys boolean>
      is_ok_to_get_access_ids?: <Can List Access Ids boolean>
      is_ok_to_get_chain_transactions?: <Can See Chain Transactions boolean>
      is_ok_to_get_invoices?: <Can See Invoices boolean>
      is_ok_to_get_wallet_info?: <Can General Graph and Wallet Information boolean>
      is_ok_to_get_payments?: <Can Get Historical Lightning Transactions boolean>
      is_ok_to_get_peers?: <Can Get Node Peers Information boolean>
      is_ok_to_pay?: <Can Send Funds or Edit Lightning Payments boolean>
      is_ok_to_revoke_access_ids?: <Can Revoke Access Ids boolean>
      is_ok_to_send_to_chain_addresses?: <Can Send Coins On Chain boolean>
      is_ok_to_sign_bytes?: <Can Sign Bytes From Node Keys boolean>
      is_ok_to_sign_messages?: <Can Sign Messages From Node Key boolean>
      is_ok_to_stop_daemon?: <Can Terminate Node or Change Operation Mode boolean>
      is_ok_to_verify_bytes_signatures?: <Can Verify Signatures of Bytes boolean>
      is_ok_to_verify_messages?: <Can Verify Messages From Node Keys boolean>
      lnd: <Authenticated LND>
      permissions]: [<Entity:Action string>?
    }

    @returns via cbk or Promise
    {
      macaroon: <Base64 Encoded Macaroon string>
      permissions: <Entity:Action string>?
    }

```node
const {createInvoice, grantAccess} = require('ln-service');

// Make a macaroon that can only create invoices
const {macaroon} = await grantAccess({lnd, is_ok_to_create_invoices: true});

// LND connection using the node cert and socket, with the restricted macaroon
const createInvoices = authenticatedLndGrpc({cert, macaroon, socket});

// Payment requests can be made with this special limited LND connection
const {request} = await createInvoice({lnd: createInvoices.lnd, tokens: 1});
```

### grpcProxyServer

Get a gRPC proxy server

    {
      bind?: <Bind to Address string>
      cert?: <LND Cert Base64 string>
      log: <Log Function>
      path: <Router Path string>
      port: <Listen Port number>
      socket: <LND Socket string>
      stream: <Log Write Stream Object>
    }

    @returns
    {
      app: <Express Application Object>
      server: <Web Server Object>
      wss: <WebSocket Server Object>
    }

```node
const {getWalletInfo} = require('ln-service');
const {lndGateway} = require('lightning');
const request = require('@alexbosworth/request');
const websocket = require('ws');
const {Writable} = require('stream');

const log = output => console.log(output);
const path = '/lnd/';
const port = 8050;

const {app, server, wss} = grpcProxyServer({
  log,
  path,
  port,
  cert: base64Encoded64TlsCertFileString,
  socket: 'localhost:10009',
  stream: new Writable({write: (chunk, encoding, cbk) => cbk()}),
});

// Create an authenticated LND for the gRPC REST gateway
const {lnd} = lndGateway({
  request,
  macaroon: base64EncodedMacaroonFileString,
  url: `http://localhost:${port}${path}`,
});

// Make a request to a gRPC method through the REST proxy
const nodeInfo = await getWalletInfo({lnd});
```

### isDestinationPayable

Determine if a payment destination is actually payable by probing it

Requires `offchain:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Pay to Node with Public Key Hex string>
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens To Pay number>
      max_timeout_height?: <Maximum Expiration CLTV Timeout Height number>
      outgoing_channel?: <Pay Out of Outgoing Standard Format Channel Id string>
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      routes?: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens?: <Paying Tokens number>
    }

    @returns via cbk or Promise
    {
      is_payable: <Payment Is Successfully Tested Within Constraints boolean>
    }

Example:

```node
const {decodePaymentRequest, isDestinationPayable} = require('ln-service');
const request = 'lnbc1pvjluezpp5qqqsyq...';
const {destination, tokens} = await decodePaymentRequest({lnd, request});
const isPayable = (await isDestinationPayable({lnd, }))
```

### lockUtxo

Lock UTXO

Requires `onchain:write` permission

Requires LND built with `walletrpc` build tag

    {
      id?: <Lock Identifier Hex string>
      lnd: <Authenticated LND>
      transaction_id: <Unspent Transaction Id Hex string>
      transaction_vout: <Unspent Transaction Output Index number>
    }

    @returns via cbk or Promise
    {
      expires_at: <Lock Expires At ISO 8601 Date string>
      id: <Locking Id Hex string>
    }

Example:

```node
const {getUtxos, lockUtxo, sendToChainAddress} = require('ln-service');

// Assume a wallet that has only one UTXO
const utxo? = (await getUtxos({lnd})).utxos;

const locked = await lockUtxo({
  lnd,
  transaction_id: utxo.transaction_id,
  transaction_vout: utxo.transaction_vout,
});

const futureUnlockDate = new Date(locked.expires_at);

// This call will throw an error as LND will treat the UTXO as being locked
await sendToChainAddress({address, lnd, tokens});
```

### openChannel

Open a new channel.

The capacity of the channel is set with local_tokens

If give_tokens is set, it is a gift and it does not alter the capacity

Requires `offchain:write`, `onchain:write`, `peers:write` permissions

    {
      chain_fee_tokens_per_vbyte?: <Chain Fee Tokens Per VByte number>
      cooperative_close_address?: <Restrict Cooperative Close To Address string>
      give_tokens?: <Tokens to Gift To Partner number> // Defaults to zero
      is_private?: <Channel is Private boolean> // Defaults to false
      lnd: <Authenticated LND>
      local_tokens: <Local Tokens number>
      min_confirmations?: <Spend UTXOs With Minimum Confirmations number>
      min_htlc_mtokens?: <Minimum HTLC Millitokens string>
      partner_public_key: <Public Key Hex string>
      partner_csv_delay?: <Peer Output CSV Delay number>
      partner_socket?: <Peer Connection Host:Port string>
    }

    @returns via cbk or Promise
    {
      transaction_id: <Funding Transaction Id string>
      transaction_vout: <Funding Transaction Output Index number>
    }

Example:

```node
const {openChannel} = require('ln-service');  
const publicKey = 'publicKeyHexString';
const tokens = 1000000;
await openChannel({lnd, local_tokens: tokens, partner_public_key: publicKey});
```

### openChannels

Open one or more channels

Requires `offchain:write`, `onchain:write` permissions

After getting the addresses and tokens to fund, use `fundChannels` within ten
minutes to fund the channels.

If you do not fund the channels, be sure to `cancelPendingChannel`s on each
channel that was not funded.

    {
      channels: [{
        capacity: <Channel Capacity Tokens number>
        cooperative_close_address?: <Restrict Coop Close To Address string>
        give_tokens?: <Tokens to Gift To Partner number> // Defaults to zero
        is_private?: <Channel is Private boolean> // Defaults to false
        min_htlc_mtokens?: <Minimum HTLC Millitokens string>
        partner_public_key: <Public Key Hex string>
        partner_csv_delay?: <Peer Output CSV Delay number>
        partner_socket?: <Peer Connection Host:Port string>
      }]
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      pending: [{
        address: <Address To Send To string>
        id: <Pending Channel Id Hex string>
        tokens: <Tokens to Send number>
      }]
    }

Example:

```node
const {fundPendingChannels, openChannels} = require('ln-service');

const channelsToOpen = {capacity: 1e6, partner_public_key: publicKey}?;

const {pending} = await openChannels({lnd, channels: channelsToOpen});

const channels = pending.map(n => n.id);

await fundPendingChannels({lnd, channels, funding: hexEncodedPsbt});
```

### parsePaymentRequest

Parse a BOLT 11 payment request into its component data

Note: either description or description_hash will be returned

    {
      request: <BOLT 11 Payment Request string>
    }

    @throws
    <ExpectedLnPrefix Error>
    <ExpectedPaymentHash Error>
    <ExpectedPaymentRequest Error>
    <ExpectedValidHrpForPaymentRequest Error>
    <FailedToParsePaymentRequestDescriptionHash Error>
    <FailedToParsePaymentRequestFallbackAddress Error>
    <FailedToParsePaymentRequestPaymentHash Error>
    <InvalidDescriptionInPaymentRequest Error>
    <InvalidOrMissingSignature Error>
    <InvalidPaymentHashByteLength Error>
    <InvalidPaymentRequestPrefix Error>
    <UnknownCurrencyCodeInPaymentRequest Error>

    @returns
    {
      chain_addresses]: [<Chain Address string>?
      cltv_delta: <CLTV Delta number>
      created_at: <Invoice Creation Date ISO 8601 string>
      description?: <Description string>
      description_hash?: <Description Hash Hex string>
      destination: <Public Key string>
      expires_at: <ISO 8601 Date string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_required: <Feature Support is Required To Pay boolean>
        type: <Feature Type string>
      }]
      id: <Payment Request Hash string>
      is_expired: <Invoice is Expired boolean>
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
      network: <Network Name string>
      payment?: <Payment Identifier Hex Encoded string>
      routes?: [[{
        base_fee_mtokens?: <Base Fee Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <Final CLTV Expiration Blocks Delta number>
        fee_rate?: <Fee Rate Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      safe_tokens?: <Requested Tokens Rounded Up number>
      tokens?: <Requested Chain Tokens number> (note: can differ from mtokens)
    }

```
const {parsePaymentRequest} = require('ln-service');
const requestDetails = parsePaymentRequest({request: 'paymentRequestString'});
```

### pay

Make a payment.

Either a payment path or a BOLT 11 payment request is required

For paying to private destinations along set paths, a public key in the route
hops is required to form the route.

Requires `offchain:write` permission

    {
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Additional Fee Tokens To Pay number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_paths?: <Maximum Simultaneous Paths number>
      max_timeout_height?: <Max CLTV Timeout number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Pay Through Outbound Standard Channel Id string>
      outgoing_channels]: [<Pay Out of Outgoing Channel Ids string>?
      path?: {
        id: <Payment Hash Hex string>
        routes: [{
          fee: <Total Fee Tokens To Pay number>
          fee_mtokens: <Total Fee Millitokens To Pay string>
          hops: [{
            channel: <Standard Format Channel Id string>
            channel_capacity: <Channel Capacity Tokens number>
            fee: <Fee number>
            fee_mtokens: <Fee Millitokens string>
            forward: <Forward Tokens number>
            forward_mtokens: <Forward Millitokens string>
            public_key?: <Public Key Hex string>
            timeout: <Timeout Block Height number>
          }]
          messages?: [{
            type: <Message Type number string>
            value: <Message Raw Value Hex Encoded string>
          }]
          mtokens: <Total Millitokens To Pay string>
          payment?: <Payment Identifier Hex string>
          timeout: <Expiration Block Height number>
          tokens: <Total Tokens To Pay number>
        }]
      }
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      request?: <BOLT 11 Payment Request string>
      tokens?: <Total Tokens To Pay to Payment Request number>
    }

    @returns via cbk or Promise
    {
      fee: <Fee Paid Tokens number>
      fee_mtokens: <Fee Paid Millitokens string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Hop Channel Capacity Tokens number>
        fee_mtokens: <Hop Forward Fee Millitokens string>
        forward_mtokens: <Hop Forwarded Millitokens string>
        timeout: <Hop CLTV Expiry Block Height number>
      }]
      id: <Payment Hash Hex string>
      is_confirmed: <Is Confirmed boolean>
      is_outgoing: <Is Outoing boolean>
      mtokens: <Total Millitokens Sent string>
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Secret Preimage Hex string>
      tokens: <Total Tokens Sent number>
    }

Example:

```node
const {pay} = require('ln-service');
const request = 'bolt11encodedpaymentrequest';
await pay({lnd, request});
```

### payViaPaymentDetails

Pay via payment details

If no id is specified, a random id will be used.

Requires `offchain:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Destination Public Key string>
      features?: [{
        bit: <Feature Bit number>
      }]
      id?: <Payment Request Hash Hex string>
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens To Pay number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_paths?: <Maximum Simultaneous Paths number>
      max_timeout_height?: <Maximum Expiration CLTV Timeout Height number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Pay Out of Outgoing Channel Id string>
      outgoing_channels]: [<Pay Out of Outgoing Channel Ids string>?
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      routes: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens?: <Tokens To Pay number>
    }

    @returns via cbk or Promise
    {
      fee: <Total Fee Tokens Paid Rounded Down number>
      fee_mtokens: <Total Fee Millitokens Paid string>
      hops: [{
        channel: <First Route Standard Format Channel Id string>
        channel_capacity: <First Route Channel Capacity Tokens number>
        fee: <First Route Fee Tokens Rounded Down number>
        fee_mtokens: <First Route Fee Millitokens string>
        forward_mtokens: <First Route Forward Millitokens string>
        public_key: <First Route Public Key Hex string>
        timeout: <First Route Timeout Block Height number>
      }]
      id: <Payment Hash Hex string>
      mtokens: <Total Millitokens Paid string>
      paths: [{
        fee_mtokens: <Total Fee Millitokens Paid string>
        hops: [{
          channel: <First Route Standard Format Channel Id string>
          channel_capacity: <First Route Channel Capacity Tokens number>
          fee: <First Route Fee Tokens Rounded Down number>
          fee_mtokens: <First Route Fee Millitokens string>
          forward_mtokens: <First Route Forward Millitokens string>
          public_key: <First Route Public Key Hex string>
          timeout: <First Route Timeout Block Height number>
        }]
        mtokens: <Total Millitokens Paid string>
      }]
      safe_fee: <Total Fee Tokens Paid Rounded Up number>
      safe_tokens: <Total Tokens Paid, Rounded Up number>
      secret: <Payment Preimage Hex string>
      timeout: <Expiration Block Height number>
      tokens: <Total Tokens Paid Rounded Down number>
    }

Example:

```node
const {payViaPaymentDetails} = require('ln-service');
const destination = 'invoiceDestinationNodePublicKeyHexString';
const id = 'paymentRequestPreimageHashHexString';
const tokens = 80085;
await payViaPaymentDetails({destination, id, lnd, tokens});
```

### payViaPaymentRequest

Pay via payment request

Requires `offchain:write` permission

    {
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens To Pay number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_paths?: <Maximum Simultaneous Paths number>
      max_timeout_height?: <Maximum Height of Payment Timeout number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Pay Out of Outgoing Channel Id string>
      outgoing_channels]: [<Pay Out of Outgoing Channel Ids string>?
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      request: <BOLT 11 Payment Request string>
      tokens?: <Tokens To Pay number>
    }

    @returns via cbk or Promise
    {
      fee: <Total Fee Tokens Paid Rounded Down number>
      fee_mtokens: <Total Fee Millitokens Paid string>
      hops: [{
        channel: <First Route Standard Format Channel Id string>
        channel_capacity: <First Route Channel Capacity Tokens number>
        fee: <First Route Fee Tokens Rounded Down number>
        fee_mtokens: <First Route Fee Millitokens string>
        forward_mtokens: <First Route Forward Millitokens string>
        public_key: <First Route Public Key Hex string>
        timeout: <First Route Timeout Block Height number>
      }]
      id: <Payment Hash Hex string>
      mtokens: <Total Millitokens Paid string>
      paths: [{
        fee_mtokens: <Total Fee Millitokens Paid string>
        hops: [{
          channel: <First Route Standard Format Channel Id string>
          channel_capacity: <First Route Channel Capacity Tokens number>
          fee: <First Route Fee Tokens Rounded Down number>
          fee_mtokens: <First Route Fee Millitokens string>
          forward_mtokens: <First Route Forward Millitokens string>
          public_key: <First Route Public Key Hex string>
          timeout: <First Route Timeout Block Height number>
        }]
        mtokens: <Total Millitokens Paid string>
      }]
      safe_fee: <Total Fee Tokens Paid Rounded Up number>
      safe_tokens: <Total Tokens Paid, Rounded Up number>
      secret: <Payment Preimage Hex string>
      timeout: <Expiration Block Height number>
      tokens: <Total Tokens Paid Rounded Down number>
    }

Example:

```node
const {payViaPaymentRequest} = require('ln-service');
const request = 'bolt11PaymentRequestString';
await payViaPaymentRequest({lnd, request});
```

### payViaRoutes

Make a payment via a specified route

If no id is specified, a random id will be used to send a test payment

Requires `offchain:write` permission

    {
      id?: <Payment Hash Hex string>
      lnd: <Authenticated LND>
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      routes: [{
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key?: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Millitokens To Pay string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
      }]
    }

    @returns via cbk or Promise
    {
      failures: [[
        <Failure Code number>
        <Failure Code Message string>
        <Failure Code Details Object>
      ]]
      fee: <Fee Paid Tokens number>
      fee_mtokens: <Fee Paid Millitokens string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Hop Channel Capacity Tokens number>
        fee_mtokens: <Hop Forward Fee Millitokens string>
        forward_mtokens: <Hop Forwarded Millitokens string>
        timeout: <Hop CLTV Expiry Block Height number>
      }]
      id: <Payment Hash Hex string>
      is_confirmed: <Is Confirmed boolean>
      is_outgoing: <Is Outoing boolean>
      mtokens: <Total Millitokens Sent string>
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Secret Preimage Hex string>
      tokens: <Total Tokens Sent Rounded Down number>
    }

    @returns error via cbk or Promise
    [
      <Error Classification Code number>
      <Error Type string>
      {
        failures: [[
          <Failure Code number>
          <Failure Code Message string>
          <Failure Code Details Object>
        ]]
      }
    ]

Example:

```node
const {getRouteToDestination, payViaRoutes} = require('ln-service');
const destination = 'destinationPublicKeyHexString';
const tokens = 80085;
const {route} = await getRouteToDestination({destination, lnd, tokens});
const preimage = (await payViaRoutes({lnd, routes: route?})).secret;
```

### prepareForChannelProposal

Prepare for a channel proposal

Channel proposals can be made with `propose_channel`. Channel proposals can
allow for cooperative close delays or external funding flows.

Requires `offchain:write`, `onchain:write` permissions

    {
      cooperative_close_delay?: <Cooperative Close Relative Delay number>
      id?: <Pending Id Hex string>
      key_index: <Channel Funding Output Multisig Local Key Index number>
      lnd: <Authenticated LND>
      remote_key: <Channel Funding Partner Multisig Public Key Hex string>
      transaction_id: <Funding Output Transaction Id Hex string>
      transaction_vout: <Funding Output Transaction Output Index number>
    }

    @returns via cbk or Promise
    {
      id: <Pending Channel Id Hex string>
    }

Example:

```node
const {getPublicKey, prepareForChannelProposal} = require('ln-service');

const {id} = await prepareForChannelProposal({
  lnd: lndAlice,
  key_index: (await getPublicKey({family: 0, lnd: lndAlice})).index,
  remote_key: (await getPublicKey({family: 0, lnd: lndBob})).public_key,
  transaction_id: transactionId, // Form an outpoint paying to 2:2 of keys
  transaction_vout: transactionVout,
});
```

### probeForRoute

Probe to find a successful route

Requires `offchain:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Destination Public Key Hex string>
      features?: [{
        bit: <Feature Bit number>
      }]
      ignore?: [{
        channel?: <Channel Id string>
        from_public_key: <Public Key Hex string>
        to_public_key?: <To Public Key Hex string>
      }]
      incoming_peer?: <Incoming Peer Public Key Hex string>
      is_ignoring_past_failures?: <Adjust Probe For Past Routing Failures boolean>
      is_strict_hints?: <Only Route Through Specified Paths boolean>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_timeout_height?: <Maximum Height of Payment Timeout number>
      messages?: [{
        type: <Message To Final Destination Type number string>
        value: <Message To Final Destination Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Outgoing Channel Id string>
      path_timeout_ms?: <Time to Spend On A Path Milliseconds number>
      payment?: <Payment Identifier Hex string>
      probe_timeout_ms?: <Probe Timeout Milliseconds number>
      routes?: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens number>
        channel_capacity?: <Channel Capacity Tokens number>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens: <Tokens number>
      total_mtokens?: <Total Millitokens Across Paths string>
    }

    @returns via cbk or Promise
    {
      route?: {
        confidence?: <Route Confidence Score Out Of One Million number>
        fee: <Route Fee Tokens Rounded Down number>
        fee_mtokens: <Route Fee Millitokens string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Forward Edge Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
        payment?: <Payment Identifier Hex string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Tokens Rounded Up number>
        timeout: <Timeout Block Height number>
        tokens: <Total Fee-Inclusive Tokens Rounded Down number>
        total_mtokens?: <Total Millitokens string>
      }
    }

Example:

```node
const {probeForRoute} = require('ln-service');
const destination = 'destinationNodePublicKeyHexString';
const tokens = 80085;
const {route} = await probeForRoute({destination, lnd, tokens});
```

### proposeChannel

Propose a new channel to a peer that prepared for the channel proposal

Channel proposals can allow for cooperative close delays or external funding
flows.

Requires `offchain:write`, `onchain:write` permissions

Requires LND compiled with `walletrpc` build tag

    {
      capacity: <Channel Capacity Tokens number>
      cooperative_close_address?: <Restrict Cooperative Close To Address string>
      cooperative_close_delay?: <Cooperative Close Relative Delay number>
      give_tokens?: <Tokens to Gift To Partner number> // Defaults to zero
      id: <Pending Channel Id Hex string>
      is_private?: <Channel is Private boolean> // Defaults to false
      key_index: <Channel Funding Output MultiSig Local Key Index number>
      lnd: <Authenticated LND>
      partner_public_key: <Public Key Hex string>
      remote_key: <Channel Funding Partner MultiSig Public Key Hex string>
      transaction_id: <Funding Output Transaction Id Hex string>
      transaction_vout: <Funding Output Transaction Output Index number>
    }

    @returns via cbk or Promise

```node
const {getPublicKey, prepareForChannelProposal} = require('ln-service');
const {getIdentity, proposeChannel} = require('ln-service');

// Alice and Bob need to have keys in the 2:2 funding output:
const aliceKey = await getPublicKey({family: 0, lnd: lndAlice});
const bobKey = await getPublicKey({family: 0, lnd: lndBob});

// Prepare for a chan that the initiator cannot cooperatively close for n blocks
const {id} = await prepareForChannelProposal({
  cooperative_close_delay: 144,
  lnd: lndAlice,
  key_index: aliceKey.index,
  remote_key: bobKey.public_key,
  transaction_id: transactionId, // Form an outpoint paying to 2:2 of above keys
  transaction_vout: transactionVout,
});

// Propose a channel that cannot be cooperatively closed for n blocks
await proposeChannel({
  id,
  capacity: 1000000, // Outpoint value
  cooperative_close_delay: 144,
  key_index: bobKey.index,
  lnd: lndBob,
  partner_public_key: (await getIdentity({lnd: lndAlice})).public_key,
  remote_key: aliceKey.public_key,
  transaction_id: transactionId, // Form an outpoint paying to 2:2 of above keys
  transaction_vout: transactionVout,
});
```

### recoverFundsFromChannel

Verify and restore a channel from a single channel backup

Requires `offchain:write` permission

    {
      backup: <Backup Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {getBackup, recoverFundsFromChannel} = require('ln-service');
const {backup} = await getBackup({lnd, transaction_id: id, transaction_vout: i});
await recoverFundsFromChannel({backup, lnd});
```

### recoverFundsFromChannels

Verify and restore channels from a multi-channel backup

Requires `offchain:write` permission

    {
      backup: <Backup Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {getBackups, recoverFundsFromChannels} = require('ln-service');
const {backup} = await getBackups({lnd});
await recoverFundsFromChannels({backup, lnd});
```

### removePeer

Remove a peer if possible

Requires `peers:remove` permission

    {
      lnd: <Authenticated LND>
      public_key: <Public Key Hex string>
    }

    @returns via cbk or Promise

Example:

```node
const {removePeer} = require('ln-service');
const connectedPeerPublicKey = 'nodePublicKeyHexString';
await removePeer({lnd, public_key: connectedPeerPublicKey});
```

### restrictMacaroon

Restrict an access macaroon

    {
      expires_at?: <Expires At ISO 8601 Date string>
      ip?: <IP Address string>
      macaroon: <Base64 Encoded Macaroon string>
    }

    @throws
    <Error>

    @returns
    {
      macaroon: <Restricted Base64 Encoded Macaroon string>
    }

Example:

```node
const {restrictMacaroon} = require('ln-service');

// Limit a macaroon to be only usable on localhost
const restrictedMacaroon = restrictMacaroon({ip: '127.0.0.1', macaroon}).macaroon;
```

### revokeAccess

Revoke an access token given out in the past

Note: this method is not supported in LND versions 0.11.0 and below

Requires `macaroon:write` permission

    {
      id: <Access Token Macaroon Root Id Positive Integer string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {grantAccess, revokeAccess} = require('ln-service');

// Create a macaroon that can be used to make off-chain payments
const {macaroon} = await grantAccess({lnd, id: '1', is_ok_to_pay: true});

// Revoke the access granted to the id
await revokeAccess({lnd, id: '1'})

// The macaroon and any others on the same id can no longer be used
```

### routeFromChannels

Get a route from a sequence of channels

Either next hop destination in channels or final destination is required

    {
      channels: [{
        capacity: <Maximum Tokens number>
        destination?: <Next Node Public Key Hex string>
        id: <Standard Format Channel Id string>
        policies: [{
          base_fee_mtokens: <Base Fee Millitokens string>
          cltv_delta: <Locktime Delta number>
          fee_rate: <Fees Charged Per Million Tokens number>
          is_disabled: <Channel Is Disabled boolean>
          min_htlc_mtokens: <Minimum HTLC Millitokens Value string>
          public_key: <Node Public Key string>
        }]
      }]
      cltv_delta?: <Final CLTV Delta number>
      destination?: <Destination Public Key Hex string>
      height: <Current Block Height number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens: <Millitokens To Send string>
      payment?: <Payment Identification Value Hex string>
      total_mtokens?: <Sum of Shards Millitokens string>
    }

    @throws
    <Error>

    @returns
    {
      route: {
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key?: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
        payment?: <Payment Identification Value Hex string>
        timeout: <Timeout Block Height number>
        tokens: <Total Fee-Inclusive Tokens number>
        total_mtokens?: <Sum of Shards Millitokens string>
      }
    }

Example:

```node
const {getChannel, getChannels, routeFromChannels} = require('ln-service');
const {getHeight} = require('ln-service');
const {id}? = await getChannels({lnd});
const channels = (await getChannel({lnd, id}))?;
const destination = 'destinationNodePublicKeyHexString';
const height = (await getHeight({lnd})).current_block_height;
const mtokens = '1000';
const res = routeFromChannels({channels, destination, height, mtokens});
const {route} = res;
```

### sendToChainAddress

Send tokens in a blockchain transaction.

Requires `onchain:write` permission

`utxo_confirmations` is not supported on LND 0.11.1 or below

    {
      address: <Destination Chain Address string>
      description?: <Transaction Label string>
      fee_tokens_per_vbyte?: <Chain Fee Tokens Per Virtual Byte number>
      is_send_all?: <Send All Funds boolean>
      lnd: <Authenticated LND>
      log?: <Log Function>
      target_confirmations?: <Confirmations To Wait number>
      tokens: <Tokens To Send number>
      utxo_confirmations?: <Minimum Confirmations for UTXO Selection number>
      wss]: [<Web Socket Server Object>?
    }

    @returns via cbk or Promise
    {
      confirmation_count: <Total Confirmations number>
      id: <Transaction Id Hex string>
      is_confirmed: <Transaction Is Confirmed boolean>
      is_outgoing: <Transaction Is Outgoing boolean>
      tokens: <Transaction Tokens number>
    }

Example:

```node
const {sendToChainAddress} = require('ln-service');
const address = 'regularOnChainAddress';
const tokens = 80085;
await sendToChainAddress({address, lnd, tokens});
```

### sendToChainAddresses

Send tokens to multiple destinations in a blockchain transaction.

Requires `onchain:write` permission

`utxo_confirmations` is not supported on LND 0.11.1 or below

    {
      description?: <Transaction Label string>
      fee_tokens_per_vbyte?: <Chain Fee Tokens Per Virtual Byte number>
      lnd: <Authenticated LND>
      log?: <Log Function>
      send_to: [{
        address: <Address string>
        tokens: <Tokens number>
      }]
      target_confirmations?: <Confirmations To Wait number>
      utxo_confirmations?: <Minimum Confirmations for UTXO Selection number>
      wss]: [<Web Socket Server Object>?
    }

    @returns via cbk or Promise
    {
      confirmation_count: <Total Confirmations number>
      id: <Transaction Id Hex string>
      is_confirmed: <Transaction Is Confirmed boolean>
      is_outgoing: <Transaction Is Outgoing boolean>
      tokens: <Transaction Tokens number>
    }

Example:

```node
const {sendToChainAddresses} = require('ln-service');
const sendTo = {address: 'onChainAddress', tokens: 80085}?;
await sendToChainAddresses({lnd, send_to: sendTo});
```

### setAutopilot

Configure Autopilot settings

Either `candidate_nodes` or `is_enabled` is required
Candidate node scores range from 1 to 100,000,000

Permissions `info:read`, `offchain:write`, `onchain:write` are required

    {
      candidate_nodes?: [{
        public_key: <Node Public Key Hex string>
        score: <Score number>
      }]
      is_enabled?: <Enable Autopilot boolean>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {setAutopilot} = require('ln-service');
await setAutopilot({is_enabled: false, lnd});
```

### settleHodlInvoice

Settle HODL invoice

Requires LND built with `invoicesrpc` build tag

Requires `invoices:write` permission

    {
      lnd: <Authenticated LND>
      secret: <Payment Preimage Hex string>
    }

    @returns via cbk or Promise

Example:

```node
const {randomBytes} = require('crypto');
const {settleHodlInvoice} = require('ln-service');

const secret = randomBytes(32).toString('hex');

// Use the sha256 hash of that secret as the id of a createHodlInvoice

// Wait for the invoice to be held (subscribeToInvoice) and then settle:
await settleHodlInvoice({lnd, secret});
```

### signBytes

Sign a sha256 hash of arbitrary bytes

Requires LND built with `signrpc` build tag

Requires `signer:generate` permission

    {
      key_family: <Key Family number>
      key_index: <Key Index number>
      lnd: <Authenticated LND>
      preimage: <Bytes To Hash and Sign Hex Encoded string>
    }

    @returns via cbk or Promise
    {
      signature: <Signature Hex string>
    }

Example:

```node
const {signBytes} = require('ln-service');

// Get signature for preimage using node identity key
const {signature} = await signBytes({
  lnd,
  key_family: 6,
  key_index: 0,
  preimage: '00',
});
```

### signMessage

Sign a message

Requires `message:write` permission

    {
      lnd: <Authenticated LND>
      message: <Message string>
    }

    @returns via cbk or Promise
    {
      signature: <Signature string>
    }

Example:

```node
const {signMessage} = require('ln-service');
const {signature} = await signMessage({lnd, message: 'hello world'});
```

### signPsbt

Sign a PSBT to produce a finalized PSBT that is ready to broadcast

Requires `onchain:write` permission

Requires LND built with `walletrpc` tag

This method is not supported in LND 0.11.1 and below

    {
      lnd: <Authenticated LND>
      psbt: <Funded PSBT Hex string>
    }

    @returns via cbk or Promise
    {
      psbt: <Finalized PSBT Hex string>
      transaction: <Signed Raw Transaction Hex string>
    }

Example:

```node
const {fundPsbt, signPsbt} = require('ln-service');

const address = 'chainAddress';
const tokens = 1000000;

// Create an unsigned PSBT that sends 1mm to a chain address
const {psbt} = await fundPsbt({lnd, outputs: {address, tokens}?});

// Get a fully signed transaction from the unsigned PSBT
const {transaction} = await signPsbt({lnd, psbt});
```

### signTransaction

Sign transaction

Requires LND built with `signerrpc` build tag

Requires `signer:generate` permission

    {
      inputs: [{
        key_family: <Key Family number>
        key_index: <Key Index number>
        output_script: <Output Script Hex string>
        output_tokens: <Output Tokens number>
        sighash: <Sighash Type number>
        vin: <Input Index To Sign number>
        witness_script: <Witness Script Hex string>
      }]
      lnd: <Authenticated LND>
      transaction: <Unsigned Transaction Hex string>
    }

    @returns via cbk or Promise
    {
      signatures: <Signature Hex string>?
    }

Example:

```node
const {signTransaction} = require('ln-service');
const {signatures} = await signTransaction({inputs, lnd, transaction});
```

### stopDaemon

Stop the Lightning daemon.

Requires `info:write` permission

    {
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {stopDaemon} = require('ln-service');
await stopDaemon({lnd});
```

### subscribeToBackups

Subscribe to backup snapshot updates

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'backup'
    {
      backup: <Backup Hex string>
      channels: [{
        backup: <Backup Hex string>
        transaction_id: <Funding Transaction Id Hex string>
        transaction_vout: <Funding Transaction Output Index number>
      }]
    }

Example:

```node
const {subscribeToBackups} = require('ln-service');
const sub = subscribeToBackups({lnd});
let currentBackup;
sub.on('backup', ({backup}) => currentBackup = backup);
```

### subscribeToBlocks

Subscribe to blocks

Requires LND built with `chainrpc` build tag

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'block'
    {
      height: <Block Height number>
      id: <Block Hash string>
    }

Example:

```node
const {subscribeToBlocks} = require('ln-service');
let chainTipBlockHash;
const sub = subscribeToBlocks({lnd});
sub.on('block', ({id}) => chainTipBlockHash = id);
```

### subscribeToChainAddress

Subscribe to confirmation details about transactions sent to an address

One and only one chain address or output script is required

Requires LND built with `chainrpc` build tag

Requires `onchain:read` permission

    {
      bech32_address?: <Address string>
      lnd: <Chain RPC LND>
      min_confirmations?: <Minimum Confirmations number>
      min_height: <Minimum Transaction Inclusion Blockchain Height number>
      output_script?: <Output Script Hex string>
      p2pkh_address?: <Address string>
      p2sh_address?: <Address string>
      transaction_id?: <Blockchain Transaction Id string>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'confirmation'
    {
      block: <Block Hash Hex string>
      height: <Block Best Chain Height number>
      transaction: <Raw Transaction Hex string>
    }

    @event 'reorg'

Example:

```node
const {subscribeToChainAddress} = require('ln-service');
const address = 'bech32Address';
let confirmationBlockHash;
const sub = subscribeToChainAddress({lnd, bech32_address: address});
sub.on('confirmation', ({block}) => confirmationBlockHash = block);
```

### subscribeToChainSpend

Subscribe to confirmations of a spend

A chain address or raw output script is required

Requires LND built with `chainrpc` build tag

Requires `onchain:read` permission

    {
      bech32_address?: <Bech32 P2WPKH or P2WSH Address string>
      lnd: <Authenticated LND>
      min_height: <Minimum Transaction Inclusion Blockchain Height number>
      output_script?: <Output Script AKA ScriptPub Hex string>
      p2pkh_address?: <Pay to Public Key Hash Address string>
      p2sh_address?: <Pay to Script Hash Address string>
      transaction_id?: <Blockchain Transaction Id Hex string>
      transaction_vout?: <Blockchain Transaction Output Index number>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'confirmation'
    {
      height: <Confirmation Block Height number>
      transaction: <Raw Transaction Hex string>
      vin: <Spend Outpoint Index number>
    }

    @event 'reorg'

Example:

```node
const {subscribeToChainSpend} = require('ln-service');
const address = 'bech32Address';
let confirmationHeight;
const sub = subscribeToChainSpend({lnd, bech32_address: address});
sub.on('confirmation', ({height}) => confirmationHeight = height);
```

### subscribeToChannels

Subscribe to channel updates

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'channel_active_changed'
    {
      is_active: <Channel Is Active boolean>
      transaction_id: <Channel Funding Transaction Id string>
      transaction_vout: <Channel Funding Transaction Output Index number>
    }

    @event 'channel_closed'
    {
      capacity: <Closed Channel Capacity Tokens number>
      close_balance_spent_by?: <Channel Balance Output Spent By Tx Id string>
      close_balance_vout?: <Channel Balance Close Tx Output Index number>
      close_confirm_height?: <Channel Close Confirmation Height number>
      close_payments: [{
        is_outgoing: <Payment Is Outgoing boolean>
        is_paid: <Payment Is Claimed With Preimage boolean>
        is_pending: <Payment Resolution Is Pending boolean>
        is_refunded: <Payment Timed Out And Went Back To Payer boolean>
        spent_by?: <Close Transaction Spent By Transaction Id Hex string>
        tokens: <Associated Tokens number>
        transaction_id: <Transaction Id Hex string>
        transaction_vout: <Transaction Output Index number>
      }]
      close_transaction_id?: <Closing Transaction Id Hex string>
      final_local_balance: <Channel Close Final Local Balance Tokens number>
      final_time_locked_balance: <Closed Channel Timelocked Tokens number>
      id?: <Closed Standard Format Channel Id string>
      is_breach_close: <Is Breach Close boolean>
      is_cooperative_close: <Is Cooperative Close boolean>
      is_funding_cancel: <Is Funding Cancelled Close boolean>
      is_local_force_close: <Is Local Force Close boolean>
      is_partner_closed?: <Channel Was Closed By Channel Peer boolean>
      is_partner_initiated?: <Channel Was Initiated By Channel Peer boolean>
      is_remote_force_close: <Is Remote Force Close boolean>
      partner_public_key: <Partner Public Key Hex string>
      transaction_id: <Channel Funding Transaction Id Hex string>
      transaction_vout: <Channel Funding Output Index number>
    }

    @event 'channel_opened'
    {
      capacity: <Channel Token Capacity number>
      commit_transaction_fee: <Commit Transaction Fee number>
      commit_transaction_weight: <Commit Transaction Weight number>
      cooperative_close_address?: <Coop Close Restricted to Address string>
      cooperative_close_delay_height?: <Prevent Coop Close Until Height number>
      id: <Standard Format Channel Id string>
      is_active: <Channel Active boolean>
      is_closing: <Channel Is Closing boolean>
      is_opening: <Channel Is Opening boolean>
      is_partner_initiated: <Channel Partner Opened Channel boolean>
      is_private: <Channel Is Private boolean>
      is_static_remote_key: <Remote Key Is Static boolean>
      local_balance: <Local Balance Tokens number>
      local_given?: <Local Initially Pushed Tokens number>
      local_reserve: <Local Reserved Tokens number>
      partner_public_key: <Channel Partner Public Key string>
      pending_payments: [{
        id: <Payment Preimage Hash Hex string>
        is_outgoing: <Payment Is Outgoing boolean>
        timeout: <Chain Height Expiration number>
        tokens: <Payment Tokens number>
      }]
      received: <Received Tokens number>
      remote_balance: <Remote Balance Tokens number>
      remote_given?: <Remote Initially Pushed Tokens number>
      remote_reserve: <Remote Reserved Tokens number>
      sent: <Sent Tokens number>
      transaction_id: <Blockchain Transaction Id string>
      transaction_vout: <Blockchain Transaction Vout number>
      unsettled_balance: <Unsettled Balance Tokens number>
    }

    @event 'channel_opening'
    {
      transaction_id: <Blockchain Transaction Id Hex string>
      transaction_vout: <Blockchain Transaction Output Index number>
    }

Example:

```node
const {once} = require('events');
const {subscribeToChannels} = require('ln-service');
const sub = subscribeToChannels({lnd});
const openedChannel? = await once(sub, 'channel_opened');
```

### subscribeToForwardRequests

Subscribe to requests to forward payments

Note that the outbound channel is only the requested channel, another may be
selected internally to complete the forward.

Requires `offchain:read`, `offchain:write` permission

`onion` is not supported in LND 0.11.1 and below

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'forward_request`
    {
      accept: () => {}
      cltv_delta: <Difference Between Out and In CLTV Height number>
      fee: <Routing Fee Tokens Rounded Down number>
      fee_mtokens: <Routing Fee Millitokens string>
      hash: <Payment Hash Hex string>
      in_channel: <Inbound Standard Format Channel Id string>
      in_payment: <Inbound Channel Payment Id number>
      messages: [{
        type: <Message Type number string>
        value: <Raw Value Hex string>
      }]
      mtokens: <Millitokens to Forward To Next Peer string>
      onion?: <Hex Serialized Next-Hop Onion Packet To Forward string>
      out_channel: <Requested Outbound Channel Standard Format Id string>
      reject: <Reject Forward Function> () => {}
      settle: <Short Circuit Function> ({secret: <Preimage Hex string}) => {}
      timeout: <CLTV Timeout Height number>
      tokens: <Tokens to Forward to Next Peer Rounded Down number>
    }

Example:

```node
const {subscribeToForwardRequests} = require('ln-service');
const sub = subscribeToForwardRequests({lnd});

sub.on('forward_request', forward => {
  // Fail all forward requests
  return forward.reject();
});
```

### subscribeToForwards

Subscribe to HTLC events

Requires `offchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <Subscription EventEmitter Object>

    @event 'error'
    <Error Object>

    @event 'forward'
    {
      at: <Forward Update At ISO 8601 Date string>
      external_failure?: <Public Failure Reason string>
      in_channel?: <Inbound Standard Format Channel Id string>
      in_payment?: <Inbound Channel Payment Id number>
      internal_failure?: <Private Failure Reason string>
      is_confirmed: <Forward Is Confirmed boolean>
      is_failed: <Forward Is Failed boolean>
      is_receive: <Is Receive boolean>
      is_send: <Is Send boolean>
      mtokens?: <Sending Millitokens number>
      out_channel?: <Outgoing Standard Format Channel Id string>
      out_payment?: <Outgoing Channel Payment Id number>
      timeout?: <Forward Timeout at Height number>
      tokens?: <Sending Tokens number>
    }

Example:

```node
const {subscribeToForwards} = require('ln-service');
const sub = subscribeToForwards({lnd});

const confirmedForwards = ?;

sub.on('forward', forward => {
  if (!forward.is_confirmed) {
    return;
  }

  return confirmedForwards.push(forward);
});
```

### subscribeToGraph

Subscribe to graph updates

Requires `info:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'channel_updated'
    {
      base_fee_mtokens: <Channel Base Fee Millitokens string>
      capacity: <Channel Capacity Tokens number>
      cltv_delta: <Channel CLTV Delta number>
      fee_rate: <Channel Fee Rate In Millitokens Per Million number>
      id: <Standard Format Channel Id string>
      is_disabled: <Channel Is Disabled boolean>
      max_htlc_mtokens?: <Channel Maximum HTLC Millitokens string>
      min_htlc_mtokens: <Channel Minimum HTLC Millitokens string>
      public_keys: <Announcing Public Key>, <Target Public Key string>?
      transaction_id: <Channel Transaction Id string>
      transaction_vout: <Channel Transaction Output Index number>
      updated_at: <Update Received At ISO 8601 Date string>
    }

    @event 'channel_closed'
    {
      capacity?: <Channel Capacity Tokens number>
      close_height: <Channel Close Confirmed Block Height number>
      id: <Standard Format Channel Id string>
      transaction_id?: <Channel Transaction Id string>
      transaction_vout?: <Channel Transaction Output Index number>
      updated_at: <Update Received At ISO 8601 Date string>
    }

    @event 'error'
    <Subscription Error>

    @event 'node_updated'
    {
      alias: <Node Alias string>
      color: <Node Color string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required boolean>
        type: <Feature Type string>
      }]
      public_key: <Node Public Key string>
      sockets]: [<Network Host And Port string>?
      updated_at: <Update Received At ISO 8601 Date string>
    }

Example:

```node
const {once} = require('events');
const {subscribeToGraph} = require('ln-service');
const sub = subscribeToGraph({lnd});
const closedChannel? = await once(sub, 'closed_channel');
```

### subscribeToInvoice

Subscribe to an invoice

LND built with `invoicesrpc` tag is required

Requires `invoices:read` permission

    {
      id: <Invoice Payment Hash Hex string>
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event `invoice_updated`
    {
      chain_address: <Fallback Chain Address string>
      confirmed_at?: <Settled at ISO 8601 Date string>
      created_at: <ISO 8601 Date string>
      description: <Description string>
      description_hash: <Description Hash Hex string>
      expires_at: <ISO 8601 Date string>
      features: [{
        bit: <BOLT 09 Feature Bit number>
        is_known: <Feature is Known boolean>
        is_required: <Feature Support is Required To Pay boolean>
        type: <Feature Type string>
      }]
      id: <Payment Hash string>
      is_canceled?: <Invoice is Canceled boolean>
      is_confirmed: <Invoice is Confirmed boolean>
      is_held?: <HTLC is Held boolean>
      is_outgoing: <Invoice is Outgoing boolean>
      is_private: <Invoice is Private boolean>
      mtokens: <Invoiced Millitokens string>
      payments: [{
        confirmed_at?: <Payment Settled At ISO 8601 Date string>
        created_at: <Payment Held Since ISO 860 Date string>
        created_height: <Payment Held Since Block Height number>
        in_channel: <Incoming Payment Through Channel Id string>
        is_canceled: <Payment is Canceled boolean>
        is_confirmed: <Payment is Confirmed boolean>
        is_held: <Payment is Held boolean>
        messages: [{
          type: <Message Type number string>
          value: <Raw Value Hex string>
        }]
        mtokens: <Incoming Payment Millitokens string>
        pending_index?: <Pending Payment Channel HTLC Index number>
        tokens: <Payment Tokens number>
      }]
      received: <Received Tokens number>
      received_mtokens: <Received Millitokens string>
      request: <Bolt 11 Invoice string>
      routes: [[{
        base_fee_mtokens: <Base Routing Fee In Millitokens number>
        channel: <Standard Format Channel Id string>
        cltv_delta: <CLTV Blocks Delta number>
        fee_rate: <Fee Rate In Millitokens Per Million number>
        public_key: <Public Key Hex string>
      }]]
      secret: <Secret Preimage Hex string>
      tokens: <Tokens number>
    }

Example:

```node
const {once} = require('events');
const {subscribeToInvoice} = require('ln-service');
const 'invoiceIdHexString';
const sub = subscribeToInvoice({id, lnd});
const invoice? = await once(sub, 'invoice_updated');
```

### subscribeToInvoices

Subscribe to invoices

Requires `invoices:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'invoice_updated'
    {
      chain_address?: <Fallback Chain Address string>
      cltv_delta: <Final CLTV Delta number>
      confirmed_at?: <Confirmed At ISO 8601 Date string>
      created_at: <Created At ISO 8601 Date string>
      description: <Description string>
      description_hash: <Description Hash Hex string>
      expires_at: <Expires At ISO 8601 Date string>
      features: [{
        bit: <Feature Bit number>
        is_known: <Is Known Feature boolean>
        is_required: <Feature Is Required boolean>
        name: <Feature Name string>
      }]
      id: <Invoice Payment Hash Hex string>
      is_confirmed: <Invoice is Confirmed boolean>
      is_outgoing: <Invoice is Outgoing boolean>
      is_push?: <Invoice is Push Payment boolean>
      payments: [{
        confirmed_at?: <Payment Settled At ISO 8601 Date string>
        created_at: <Payment Held Since ISO 860 Date string>
        created_height: <Payment Held Since Block Height number>
        in_channel: <Incoming Payment Through Channel Id string>
        is_canceled: <Payment is Canceled boolean>
        is_confirmed: <Payment is Confirmed boolean>
        is_held: <Payment is Held boolean>
        messages: [{
          type: <Message Type number string>
          value: <Raw Value Hex string>
        }]
        mtokens: <Incoming Payment Millitokens string>
        pending_index?: <Pending Payment Channel HTLC Index number>
        tokens: <Payment Tokens number>
        total_mtokens?: <Total Payment Millitokens string>
      }]
      received: <Received Tokens number>
      received_mtokens: <Received Millitokens string>
      request?: <BOLT 11 Payment Request string>
      secret: <Payment Secret Hex string>
      tokens: <Invoiced Tokens number>
    }

Example:

```node
const {once} = require('events');
const {subscribeToInvoices} = require('ln-service');
const sub = subscribeToInvoices({lnd});
const lastUpdatedInvoice? = await once(sub, 'invoice_updated');
```

### subscribeToOpenRequests

Subscribe to inbound channel open requests

Requires `offchain:write`, `onchain:write` permissions

Note: listening to inbound channel requests will automatically fail all
channel requests after a short delay.

To return to default behavior of accepting all channel requests, remove all
listeners to `channel_request`

LND 0.11.1 and below do not support `accept` or `reject` arguments

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'channel_request'
    {
      accept: <Accept Request Function> ({
        cooperative_close_address?: <Restrict Coop Close To Address string>
        min_confirmations?: <Required Confirmations Before Channel Open number>
        remote_csv?: <Peer Unilateral Balance Output CSV Delay number>
        remote_reserve?: <Minimum Tokens Peer Must Keep On Their Side number>
        remote_max_htlcs?: <Maximum Slots For Attaching HTLCs number>
        remote_max_pending_mtokens?: <Maximum HTLCs Value Millitokens string>
        remote_min_htlc_mtokens?: <Minimium HTLC Value Millitokens string>
      }) -> {}
      capacity: <Capacity Tokens number>
      chain: <Chain Id Hex string>
      commit_fee_tokens_per_vbyte: <Commitment Transaction Fee number>
      csv_delay: <CSV Delay Blocks number>
      id: <Request Id Hex string>
      local_balance: <Channel Local Tokens Balance number>
      local_reserve: <Channel Local Reserve Tokens number>
      max_pending_mtokens: <Maximum Millitokens Pending In Channel string>
      max_pending_payments: <Maximum Pending Payments number>
      min_chain_output: <Minimum Chain Output Tokens number>
      min_htlc_mtokens: <Minimum HTLC Millitokens string>
      partner_public_key: <Peer Public Key Hex string>
      reject: <Reject Request Function> ({
        reason?: <500 Character Limited Rejection Reason string>
      }) -> {}
    }

Example:

```node
const {subscribeToOpenRequests} = require('ln-service');
const sub = subscribeToOpenRequests({lnd});
sub.on('channel_request', channel => {
  // Reject small channels
  return (channel.capacity < 1000000) ? request.reject() : request.accept();
});
```

### subscribeToPastPayment

Subscribe to the status of a past payment

Requires `offchain:read` permission

    {
      id: <Payment Request Hash Hex string>
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <Subscription EventEmitter Object>

    @event 'confirmed'
    {
      fee_mtokens: <Total Fee Millitokens To Pay string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Channel Capacity Tokens number>
        fee: <Routing Fee Tokens number>
        fee_mtokens: <Fee Millitokens string>
        forward: <Forwarded Tokens number>
        forward_mtokens: <Forward Millitokens string>
        public_key: <Public Key Hex string>
        timeout: <Timeout Block Height number>
      }]
      id: <Payment Hash Hex string>
      mtokens: <Total Millitokens Paid string>
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Preimage Hex string>
      timeout: <Expiration Block Height number>
      tokens: <Tokens Paid number>
    }

    @event 'failed'
    {
      is_insufficient_balance: <Failed Due To Lack of Balance boolean>
      is_invalid_payment: <Failed Due to Payment Rejected At Destination boolean>
      is_pathfinding_timeout: <Failed Due to Pathfinding Timeout boolean>
      is_route_not_found: <Failed Due to Absence of Path Through Graph boolean>
    }

    @event 'paying'
    {}

Exmple:

```node
const {once} = require('events');
const {subscribeToPastPayment} = require('ln-service');
const id = 'paymentRequestHashHexString';
const sub = subscribeToPastPayment({id, lnd});
const {secret} = await once(sub, 'confirmed');
```

### subscribeToPayViaDetails

Subscribe to the flight of a payment

Requires `offchain:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Destination Public Key string>
      features?: [{
        bit: <Feature Bit number>
      }]
      id?: <Payment Request Hash Hex string>
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens To Pay number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_paths?: <Maximum Simultaneous Paths number>
      max_timeout_height?: <Maximum Height of Payment Timeout number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Pay Out of Outgoing Channel Id string>
      outgoing_channels]: [<Pay Out of Outgoing Channel Ids string>?
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      routes?: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens string>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens?: <Tokens to Pay number>
    }

    @throws
    <Error>

    @returns
    <Subscription EventEmitter Object>

    @event 'confirmed'
    {
      fee: <Fee Tokens Paid number>
      fee_mtokens: <Total Fee Millitokens Paid string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Channel Capacity Tokens number>
        fee_mtokens: <Fee Millitokens string>
        forward_mtokens: <Forward Millitokens string>
        public_key: <Public Key Hex string>
        timeout: <Timeout Block Height number>
      }]
      id?: <Payment Hash Hex string>
      mtokens: <Total Millitokens To Pay string>
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Preimage Hex string>
      tokens: <Total Tokens Paid Rounded Down number>
    }

    @event 'failed'
    {
      is_insufficient_balance: <Failed Due To Lack of Balance boolean>
      is_invalid_payment: <Failed Due to Invalid Payment boolean>
      is_pathfinding_timeout: <Failed Due to Pathfinding Timeout boolean>
      is_route_not_found: <Failed Due to Route Not Found boolean>
      route?: {
        fee: <Route Total Fee Tokens Rounded Down number>
        fee_mtokens: <Route Total Fee Millitokens string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Hop Forwarding Fee Rounded Down Tokens number>
          fee_mtokens: <Hop Forwarding Fee Millitokens string>
          forward: <Hop Forwarding Tokens Rounded Down number>
          forward_mtokens: <Hop Forwarding Millitokens string>
          public_key: <Hop Sending To Public Key Hex string>
          timeout: <Hop CTLV Expiration Height number>
        }]
        mtokens: <Payment Sending Millitokens string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Sending Tokens Rounded Up number>
        timeout: <Payment CLTV Expiration Height number>
        tokens: <Payment Sending Tokens Rounded Down number>
      }
    }

    @event 'paying'
    {}

Example:

```node
const {once} = require('events');
const {subscribeToPayViaDetails} = require('ln-service');
const destination = 'destinationNodePublicKeyHexString';
const id = 'paymentRequestHashHexString';
const sub = subscribeToPayViaDetails({destination, id, lnd, tokens: 80085});
const paid? = await once(sub, 'confirmed');
```

### subscribeToPayViaRequest

Initiate and subscribe to the outcome of a payment request

Requires `offchain:write` permission

    {
      incoming_peer?: <Pay Through Specific Final Hop Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens To Pay number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Pay string>
      max_paths?: <Maximum Simultaneous Paths number>
      max_timeout_height?: <Maximum Height of Payment Timeout number>
      messages?: [{
        type: <Message Type number string>
        value: <Message Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Pay string>
      outgoing_channel?: <Pay Out of Outgoing Channel Id string>
      outgoing_channels]: [<Pay Out of Outgoing Channel Ids string>?
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      request: <BOLT 11 Payment Request string>
      tokens?: <Tokens To Pay number>
    }

    @throws
    <Error>

    @returns
    <Subscription EventEmitter Object>

    @event 'confirmed'
    {
      fee: <Fee Tokens number>
      fee_mtokens: <Total Fee Millitokens To Pay string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Channel Capacity Tokens number>
        fee_mtokens: <Fee Millitokens string>
        forward_mtokens: <Forward Millitokens string>
        public_key: <Public Key Hex string>
        timeout: <Timeout Block Height number>
      }]
      id: <Payment Hash Hex string>
      mtokens: <Total Millitokens Paid string>
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Preimage Hex string>
      timeout: <Expiration Block Height number>
      tokens: <Total Tokens Paid number>
    }

    @event 'failed'
    {
      is_insufficient_balance: <Failed Due To Lack of Balance boolean>
      is_invalid_payment: <Failed Due to Invalid Payment boolean>
      is_pathfinding_timeout: <Failed Due to Pathfinding Timeout boolean>
      is_route_not_found: <Failed Due to Route Not Found boolean>
      route?: {
        fee: <Route Total Fee Tokens Rounded Down number>
        fee_mtokens: <Route Total Fee Millitokens string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Hop Forwarding Fee Rounded Down Tokens number>
          fee_mtokens: <Hop Forwarding Fee Millitokens string>
          forward: <Hop Forwarding Tokens Rounded Down number>
          forward_mtokens: <Hop Forwarding Millitokens string>
          public_key: <Hop Sending To Public Key Hex string>
          timeout: <Hop CTLV Expiration Height number>
        }]
        mtokens: <Payment Sending Millitokens string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Sending Tokens Rounded Up number>
        timeout: <Payment CLTV Expiration Height number>
        tokens: <Payment Sending Tokens Rounded Down number>
      }
    }

    @event 'paying'
    {}

Example:

```node
const {once} = require('events');
const {subscribeToPayViaRequest} = require('ln-service');
const request = 'bolt11PaymentRequest';
const sub = subscribeToPayViaRequest({lnd, request});
const paid? = once(sub, 'confirmed');
```

### subscribeToPayViaRoutes

Subscribe to the attempts of paying via specified routes

Requires `offchain:write` permission

    {
      id?: <Payment Hash Hex string>
      lnd: <Authenticated LND>
      pathfinding_timeout?: <Time to Spend Finding a Route Milliseconds number>
      routes: [{
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Millitokens To Pay string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
      }]
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'failure'
    {
      failure: [
        <Code number>
        <Failure Message string>
        {
          channel: <Standard Format Channel Id string>
          mtokens?: <Millitokens string>
          policy?: {
            base_fee_mtokens: <Base Fee Millitokens string>
            cltv_delta: <Locktime Delta number>
            fee_rate: <Fees Charged in Millitokens Per Million number>
            is_disabled?: <Channel is Disabled boolean>
            max_htlc_mtokens: <Maximum HLTC Millitokens value string>
            min_htlc_mtokens: <Minimum HTLC Millitokens Value string>
          }
          public_key: <Public Key Hex string>
          update?: {
            chain: <Chain Id Hex string>
            channel_flags: <Channel Flags number>
            extra_opaque_data: <Extra Opaque Data Hex string>
            message_flags: <Message Flags number>
            signature: <Channel Update Signature Hex string>
          }
        }
      ]
    }

    @event 'paying'
    {
      route: {
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        mtokens: <Total Millitokens To Pay string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
      }
    }

    @event 'routing_failure'
    {
      channel?: <Standard Format Channel Id string>
      index?: <Failure Hop Index number>
      mtokens?: <Failure Related Millitokens string>
      policy?: {
        base_fee_mtokens: <Base Fee Millitokens string>
        cltv_delta: <Locktime Delta number>
        fee_rate: <Fees Charged in Millitokens Per Million number>
        is_disabled?: <Channel is Disabled boolean>
        max_htlc_mtokens: <Maximum HLTC Millitokens value string>
        min_htlc_mtokens: <Minimum HTLC Millitokens Value string>
      }
      public_key: <Public Key Hex string>
      reason: <Failure Reason string>
      route: {
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        mtokens: <Total Millitokens To Pay string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
      }
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      timeout_height?: <Failure Related CLTV Timeout Height number>
      update?: {
        chain: <Chain Id Hex string>
        channel_flags: <Channel Flags number>
        extra_opaque_data: <Extra Opaque Data Hex string>
        message_flags: <Message Flags number>
        signature: <Channel Update Signature Hex string>
      }
    }

    @event 'success'
    {
      fee: <Fee Paid Tokens number>
      fee_mtokens: <Fee Paid Millitokens string>
      hops: [{
        channel: <Standard Format Channel Id string>
        channel_capacity: <Hop Channel Capacity Tokens number>
        fee_mtokens: <Hop Forward Fee Millitokens string>
        forward_mtokens: <Hop Forwarded Millitokens string>
        timeout: <Hop CLTV Expiry Block Height number>
      }]
      id: <Payment Hash Hex string>
      is_confirmed: <Is Confirmed boolean>
      is_outgoing: <Is Outoing boolean>
      mtokens: <Total Millitokens Sent string>
      route: {
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        mtokens: <Total Millitokens To Pay string>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
      }
      safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
      safe_tokens: <Payment Tokens Rounded Up number>
      secret: <Payment Secret Preimage Hex string>
      tokens: <Total Tokens Sent number>
    }

Example:

```node
const {once} = require('events');
const {getRouteToDestination, subscribeToPayViaRoutes} = require('ln-service');
const {route} = getRouteToDestination({destination, lnd, tokens});
const sub = subscribeToPayViaRoutes({lnd, routes: route?});
const success? = await once(sub, 'success');
```

### subscribeToPeers

Subscribe to peer connectivity events

Requires `peers:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'connected'
    {
      public_key: <Connected Peer Public Key Hex string>
    }

    @event 'disconnected'
    {
      public_key: <Disconnected Peer Public Key Hex string>
    }

Example:

```node
const {subscribeToPeers} = require('ln-service');

const sub = subscribeToPeers({lnd});

let lastConnectedPeer;

// Listen to connected peers
sub.on('connected', peer => lastConnected = peer.public_key);
```

### subscribeToProbeForRoute

Subscribe to a probe attempt

Requires `offchain:write` permission

    {
      cltv_delta?: <Final CLTV Delta number>
      destination: <Destination Public Key Hex string>
      features?: [{
        bit: <Feature Bit number>
      }]
      ignore?: [{
        from_public_key: <Public Key Hex string>
        to_public_key?: <To Public Key Hex string>
      }]
      incoming_peer?: <Incoming Peer Public Key Hex string>
      lnd: <Authenticated LND>
      max_fee?: <Maximum Fee Tokens number>
      max_fee_mtokens?: <Maximum Fee Millitokens to Probe string>
      max_timeout_height?: <Maximum CLTV Timeout Height number>
      messages?: [{
        type: <Message To Final Destination Type number string>
        value: <Message To Final Destination Raw Value Hex Encoded string>
      }]
      mtokens?: <Millitokens to Probe string>
      outgoing_channel?: <Outgoing Channel Id string>
      path_timeout_ms?: <Skip Individual Path Attempt After Milliseconds number>
      payment?: <Payment Identifier Hex string>
      probe_timeout_ms?: <Fail Entire Probe After Milliseconds number>
      routes?: [[{
        base_fee_mtokens?: <Base Routing Fee In Millitokens number>
        channel_capacity?: <Channel Capacity Tokens number>
        channel?: <Standard Format Channel Id string>
        cltv_delta?: <CLTV Blocks Delta number>
        fee_rate?: <Fee Rate In Millitokens Per Million number>
        public_key: <Forward Edge Public Key Hex string>
      }]]
      tokens?: <Tokens to Probe number>
      total_mtokens?: <Total Millitokens Across Paths string>
    }

    @returns
    <Probe Subscription Event Emitter Object>

    @event 'error'
    <Failure Code number>, <Failure Message string>?

    @event 'probe_success'
    {
      route: {
        confidence?: <Route Confidence Score Out Of One Million number>
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Millitokens To Pay string>
        payment?: <Payment Identifier Hex string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Sent Tokens Rounded Up number>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
        total_mtokens?: <Total Millitokens string>
      }
    }

    @event 'probing'
    {
      route: {
        confidence?: <Route Confidence Score Out Of One Million number>
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Millitokens To Pay string>
        payment?: <Payment Identifier Hex string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Sent Tokens Rounded Up number>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
        total_mtokens?: <Total Millitokens string>
      }
    }

    @event 'routing_failure'
    {
      channel?: <Standard Format Channel Id string>
      mtokens?: <Millitokens string>
      policy?: {
        base_fee_mtokens: <Base Fee Millitokens string>
        cltv_delta: <Locktime Delta number>
        fee_rate: <Fees Charged in Millitokens Per Million number>
        is_disabled?: <Channel is Disabled boolean>
        max_htlc_mtokens: <Maximum HLTC Millitokens Value string>
        min_htlc_mtokens: <Minimum HTLC Millitokens Value string>
      }
      public_key: <Public Key Hex string>
      reason: <Failure Reason string>
      route: {
        confidence?: <Route Confidence Score Out Of One Million number>
        fee: <Total Fee Tokens To Pay number>
        fee_mtokens: <Total Fee Millitokens To Pay string>
        hops: [{
          channel: <Standard Format Channel Id string>
          channel_capacity: <Channel Capacity Tokens number>
          fee: <Fee number>
          fee_mtokens: <Fee Millitokens string>
          forward: <Forward Tokens number>
          forward_mtokens: <Forward Millitokens string>
          public_key: <Public Key Hex string>
          timeout: <Timeout Block Height number>
        }]
        messages?: [{
          type: <Message Type number string>
          value: <Message Raw Value Hex Encoded string>
        }]
        mtokens: <Total Millitokens To Pay string>
        payment?: <Payment Identifier Hex string>
        safe_fee: <Payment Forwarding Fee Rounded Up Tokens number>
        safe_tokens: <Payment Sent Tokens Rounded Up number>
        timeout: <Expiration Block Height number>
        tokens: <Total Tokens To Pay number>
        total_mtokens?: <Total Millitokens string>
      }
      update?: {
        chain: <Chain Id Hex string>
        channel_flags: <Channel Flags number>
        extra_opaque_data: <Extra Opaque Data Hex string>
        message_flags: <Message Flags number>
        signature: <Channel Update Signature Hex string>
      }
    }

Example:

```node
const {once} = require('events');
const {subscribeToProbeForRoute} = require('ln-service');
const destination = 'destinationPublicKeyHexString';
const sub = subscribeToProbeForRoute({destination, lnd, tokens: 80085});
const {route}? = await once(sub, 'probe_success');
```

### subscribeToTransactions

Subscribe to transactions

Requires `onchain:read` permission

    {
      lnd: <Authenticated LND>
    }

    @throws
    <Error>

    @returns
    <EventEmitter Object>

    @event 'chain_transaction'
    {
      block_id?: <Block Hash string>
      confirmation_count?: <Confirmation Count number>
      confirmation_height?: <Confirmation Block Height number>
      created_at: <Created ISO 8601 Date string>
      fee?: <Fees Paid Tokens number>
      id: <Transaction Id string>
      is_confirmed: <Is Confirmed boolean>
      is_outgoing: <Transaction Outbound boolean>
      output_addresses: <Address string>?
      tokens: <Tokens Including Fee number>
      transaction?: <Raw Transaction Hex string>
    }

Example:

```node
const {subscribeToTransactions} = require('ln-service');
let lastChainTransactionId;
const sub = subscribeToTransactions({lnd});
sub.on('chain_transaction', tx => lastChainTransactionId = tx.id);
```

### unauthenticatedLndGrpc

Unauthenticated gRPC interface to the Lightning Network Daemon (lnd).

Make sure to provide a cert when using LND with its default self-signed cert

    {
      cert?: <Base64 or Hex Serialized LND TLS Cert>
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
        unlocker: <Unlocker LND GRPC Api Object>
      }
    }

Example:

```node
const {createSeed, unauthenticatedLndGrpc} = require('ln-service');
const {lnd} = unauthenticatedLndGrpc({});
const {seed} = await createSeed({lnd});
```

### unlockUtxo

Unlock UTXO

Requires `onchain:write` permission

Requires LND built with `walletrpc` build tag

    {
      id: <Lock Id Hex string>
      lnd: <Authenticated LND>
      transaction_id: <Unspent Transaction Id Hex string>
      transaction_vout: <Unspent Transaction Output Index number>
    }

    @returns via cbk or Promise

Example:

```node
const {getUtxos, lockUtxo, sendToChainAddress, unlockUtxo} = require('ln-service');

// Assume a wallet that has only one UTXO
const utxo? = (await getUtxos({lnd})).utxos;

const locked = await lockUtxo({
  lnd,
  transaction_id: utxo.transaction_id,
  transaction_vout: utxo.transaction_vout,
});

const futureUnlockDate = new Date(locked.expires_at);

try {
  // This call will throw an error as LND will treat the UTXO as being locked
  await sendToChainAddress({address, lnd, tokens});
} catch (err) {
  // Insufficient funds
}

await unlockUtxo({
  lnd,
  id: locked.id,
  transaction_id: utxo.transaction_id,
  transaction_vout: utxo.transaction_vout,
});

// This call will now succeed as LND will treat the UTXO as being unlocked
await sendToChainAddress({address, lnd, tokens});
```

### unlockWallet

Unlock the wallet

    {
      lnd: <Unauthenticated LND>
      password: <Wallet Password string>
    }

    @returns via cbk or Promise

Example:

```node
const {unauthenticatedLndGrpc, unlockWallet} = require('ln-service');
const {lnd} = unauthenticatedLndGrpc({});
await unlockWallet({lnd, password: 'walletSecretPassword'});
```

### updateChainTransaction

Update an on-chain transaction record metadata

Requires LND built with `walletrpc` build tag

Requires `onchain:write` permission

    {
      description: <Transaction Label string>
      id: <Transaction Id Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise

Example:

```node
const {getChainTransactions} = require('ln-service');

const {transactions} = await getChainTransactions({lnd});

const {id}? = transactions;

await updateChainTransaction({id, lnd, description: 'First transaction'});
```

### updateConnectedWatchtower

Update a watchtower

Requires LND built with wtclientrpc build tag

    {
      add_socket?: <Add Socket string>
      lnd: <Authenticated LND>
      public_key: <Watchtower Public Key Hex string>
      remove_socket?: <Remove Socket string>
    }

    @returns via cbk or Promise

Example:

```node
const {updateConnectedWatchtower} = require('ln-service');

await updateConnectedWatchtower({
  lnd,
  add_socket: additionalWatchtowerNetworkAddress,
  public_key: watchtowerPublicKey,
});
```

### updateRoutingFees

Update routing fees on a single channel or on all channels

Setting both `base_fee_tokens` and `base_fee_mtokens` is not supported

    {
      base_fee_mtokens?: <Base Fee Millitokens Charged number>
      base_fee_tokens?: <Base Fee Tokens Charged number>
      cltv_delta?: <HTLC CLTV Delta number>
      fee_rate?: <Fee Rate In Millitokens Per Million number>
      lnd: <Authenticated LND>
      max_htlc_mtokens?: <Maximum HTLC Millitokens to Forward string>
      min_htlc_mtokens?: <Minimum HTLC Millitokens to Forward string>
      transaction_id?: <Channel Funding Transaction Id string>
      transaction_vout?: <Channel Funding Transaction Output Index number>
    }

    @returns via cbk or Promise

Example:

```node
const {updateRoutingFees} = require('lnd');
await updateRoutingFees({lnd, fee_rate: 2500});
```

### verifyBackup

Verify a channel backup

    {
      backup: <Individual Channel Backup Hex string>
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      err?: <LND Error Object>
      is_valid: <Backup is Valid boolean>
    }

Example:

```node
const {getBackups, verifyBackup} = require('ln-service');
const channelBackup? = (await getBackups({lnd})).channels;

const isValid = (await verifyBackup({lnd, backup: channelBackup.backup})).is_valid;
```

### verifyBackups

Verify a set of aggregated channel backups

    {
      backup: <Multi-Backup Hex string>
      channels: [{
        transaction_id: <Funding Transaction Id Hex string>
        transaction_vout: <Funding Transaction Output Index number>
      }]
      lnd: <Authenticated LND>
    }

    @returns via cbk or Promise
    {
      is_valid: <Backup is Valid boolean>
    }

Example:

```node
const {getBackups, verifyBackups} = require('ln-service');
const {backup, channels} = await getBackups({lnd});
const isValid = (await verifyBackups({backup, channels, lnd})).is_valid;
```

### verifyBytesSignature

Verify signature of arbitrary bytes

Requires LND built with `signrpc` build tag

Requires `signer:read` permission

    {
      lnd: <Authenticated LND>
      preimage: <Message Preimage Bytes Hex Encoded string>
      public_key: <Signature Valid For Public Key Hex string>
      signature: <Signature Hex string>
    }

    @returns via cbk or Promise
    {
      is_valid: <Signature is Valid boolean>
    }

Example:

```node
const {getIdentity, signBytes, verifyBytesSignature} = require('ln-service');

const preimage = Buffer.from('hello world').toString('hex');

// Sign the hash of the string "hello world"
const {signature} = await signBytes({lnd, preimage, key_family: 6, key_index: 0});

// Verify that the signature is good for the public key over the preimage
const validity = await verifyBytesSignature({
  lnd,
  preimage,
  signature,
  public_key: (await getIdentity({lnd})).public_key,
});
```

### verifyMessage

Verify a message was signed by a known pubkey

Requires `message:read` permission

    {
      lnd: <Authenticated LND>
      message: <Message string>
      signature: <Signature Hex string>
    }

    @returns via cbk or Promise
    {
      signed_by: <Public Key Hex string>
    }

Example:

```node
const {verifyMessage} = require('ln-service');
const message = 'foo';
const signature = 'badSignature';
const signedBy = (await verifyMessage({lnd, message, signature})).signed_by;
```

