

### addPeer

Add a peer if possible (not self, or already connected)

Requires `peers:write` permission

`timeout` is not supported in LND 0.11.1 and below

    {
/** Add Peer as Temporary Peer boolean */
      is_temporary?: boolean
/** Authenticated LND */
      lnd: LND
/** Public Key Hex string */
      public_key: string
/** Retry Count number */
      retry_count?: number
/** Delay Retry By Milliseconds number */
      retry_delay?: number
/** Host Network Address And Optional Port string */
      socket: string
/** Connection Attempt Timeout Milliseconds number */
      timeout?: number
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
/** Base64 or Hex Serialized LND TLS Cert */
      cert?: Cert
/** Base64 or Hex Serialized Macaroon string */
      macaroon: string
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
/** Autopilot API Methods Object */
        autopilot: Object
/** ChainNotifier API Methods Object */
        chain: Object
/** Default API Methods Object */
        default: Object
/** Invoices API Methods Object */
        invoices: Object
/** Router API Methods Object */
        router: Object
/** Signer Methods API Object */
        signer: Object
/** Watchtower Client Methods Object */
        tower_client: Object
/** Watchtower Server Methods API Object */
        tower_server: Object
/** WalletKit gRPC Methods API Object */
        wallet: Object
/** Version Methods API Object */
        version: Object
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
/** Transaction Label string */
      description?: string
/** Authenticated LND */
      lnd: LND
/** Transaction Hex string */
      transaction: string
    }

    @returns via cbk or Promise
    {
/** Transaction Id Hex string */
      id: string
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
/** Capacity Tokens number */
        capacity: number
/** Standard Channel Id string */
        id: string
        policies: [{
/** Base Fee Millitokens string */
          base_fee_mtokens: string
/** CLTV Delta number */
          cltv_delta: number
/** Fee Rate number */
          fee_rate: number
/** Channel is Disabled boolean */
          is_disabled: boolean
/** Maximum HTLC Millitokens string */
          max_htlc_mtokens: string
/** Minimum HTLC Millitokens string */
          min_htlc_mtokens: string
/** Public Key Hex string */
          public_key: string
        }]
      }]
/** End Public Key Hex string */
      end: string
      ignore?: [{
/** Standard Format Channel Id string */
        channel?: string
/** Public Key Hex string */
        public_key: string
      }]
/** Millitokens number */
      mtokens: number
/** Start Public Key Hex string */
      start: string
    }

    @throws
    <Error>

    @returns
    {
      hops?: [{
/** Base Fee Millitokens string */
        base_fee_mtokens: string
/** Standard Channel Id string */
        channel: string
/** Channel Capacity Tokens number */
        channel_capacity: number
/** CLTV Delta number */
        cltv_delta: number
/** Fee Rate number */
        fee_rate: number
/** Public Key Hex string */
        public_key: string
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
/** Capacity Tokens number */
        capacity: number
/** Standard Channel Id string */
        id: string
        policies: [{
/** Base Fee Millitokens string */
          base_fee_mtokens: string
/** CLTV Delta number */
          cltv_delta: number
/** Fee Rate number */
          fee_rate: number
/** Channel is Disabled boolean */
          is_disabled: boolean
/** Maximum HTLC Millitokens string */
          max_htlc_mtokens: string
/** Minimum HTLC Millitokens string */
          min_htlc_mtokens: string
/** Public Key Hex string */
          public_key: string
        }]
      }]
/** End Public Key Hex string */
      end: string
/** Paths To Return Limit number */
      limit?: number
/** Millitokens number */
      mtokens: number
/** Start Public Key Hex string */
      start: string
    }

    @throws
    <Error>

    @returns
    {
      paths?: [{
        hops: [{
/** Base Fee Millitokens string */
          base_fee_mtokens: string
/** Standard Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** CLTV Delta number */
          cltv_delta: number
/** Fee Rate number */
          fee_rate: number
/** Public Key Hex string */
          public_key: string
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
/** Payment Preimage Hash Hex string */
      id: string
/** Authenticated RPC LND */
      lnd: LND
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
/** Pending Channel Id Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
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
/** Current Password string */
      current_password: string
/** Unauthenticated LND */
      lnd: LND
/** New Password string */
      new_password: string
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
/** Request Sending Local Channel Funds To Address string */
      address?: string
/** Standard Format Channel Id string */
      id?: string
/** Is Force Close boolean */
      is_force_close?: boolean
/** Authenticated LND */
      lnd: LND
/** Peer Public Key string */
      public_key?: string
/** Peer Socket string */
      socket?: string
/** Confirmation Target number */
      target_confirmations?: number
/** Tokens Per Virtual Byte number */
      tokens_per_vbyte?: number
/** Transaction Id Hex string */
      transaction_id?: string
/** Transaction Output Index number */
      transaction_vout?: number
    }

    @returns via cbk or Promise
    {
/** Closing Transaction Id Hex string */
      transaction_id: string
/** Closing Transaction Vout number */
      transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
/** Watchtower Public Key Hex string */
      public_key: string
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
/** Receive Address Type string */
      format: string
      is_unused?: <Get As-Yet Unused Address boolean>
/** Authenticated LND */
      lnd: LND
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Invoice Description string */
      description?: string
/** Hashed Description of Payment Hex string */
      description_hash?: string
/** Expires At ISO 8601 Date string */
      expires_at?: string
/** Payment Hash Hex string */
      id?: string
/** Is Fallback Address Included boolean */
      is_fallback_included?: boolean
/** Is Fallback Address Nested boolean */
      is_fallback_nested?: boolean
/** Invoice Includes Private Channels boolean */
      is_including_private_channels?: boolean
/** Authenticated LND */
      lnd: LND
/** Millitokens string */
      mtokens?: string
/** Tokens number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Backup Address string */
      chain_address?: string
/** ISO 8601 Date string */
      created_at: string
/** Description string */
      description: string
/** Payment Hash Hex string */
      id: string
/** Millitokens number */
      mtokens: number
/** BOLT 11 Encoded Payment Request string */
      request: string
/** Hex Encoded Payment Secret string */
      secret?: string
/** Tokens number */
      tokens: number
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
/** CLTV Delta number */
      cltv_delta?: number
/** Invoice Description string */
      description?: string
/** Hashed Description of Payment Hex string */
      description_hash?: string
/** Expires At ISO 8601 Date string */
      expires_at?: string
/** Is Fallback Address Included boolean */
      is_fallback_included?: boolean
/** Is Fallback Address Nested boolean */
      is_fallback_nested?: boolean
/** Invoice Includes Private Channels boolean */
      is_including_private_channels?: boolean
/** Authenticated LND */
      lnd: LND
/** Payment Preimage Hex string */
      secret?: string
/** Millitokens string */
      mtokens?: string
/** Tokens number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Backup Address string */
      chain_address?: string
/** ISO 8601 Date string */
      created_at: string
/** Description string */
      description?: string
/** Payment Hash Hex string */
      id: string
/** Millitokens string */
      mtokens?: string
/** BOLT 11 Encoded Payment Request string */
      request: string
/** Hex Encoded Payment Secret string */
      secret: string
/** Tokens number */
      tokens?: number
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
/** Unauthenticated LND */
      lnd: LND
/** Seed Passphrase string */
      passphrase?: string
    }

    @returns via cbk or Promise
    {
/** Cipher Seed Mnemonic string */
      seed: string
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
/** Destination Public Key Hex string */
      destination: string
/** Request Human Readable Part string */
      hrp: string
/** Request Hash Signature Hex string */
      signature: string
/** Request Tag Word number */
      tags: number
    }

    @throws
    <Error>

    @returns
    {
/** BOLT 11 Encoded Payment Request string */
      request: string
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
/** Chain Address string */
      chain_addresses]: [string
/** CLTV Delta number */
      cltv_delta?: number
/** Invoice Creation Date ISO 8601 string */
      created_at?: string
/** Description string */
      description?: string
/** Description Hash Hex string */
      description_hash?: string
/** Public Key string */
      destination: string
/** ISO 8601 Date string */
      expires_at?: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
      }]
/** Preimage SHA256 Hash Hex string */
      id: string
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
/** Network Name string */
      network: string
/** Payment Identifier Hex string */
      payment?: string
      routes?: [[{
/** Base Fee Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** Final CLTV Expiration Blocks Delta number */
        cltv_delta?: number
/** Fees Charged in Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Requested Chain Tokens number */
      tokens?: number
    }

    @returns
    {
/** Payment Request Signature Hash Hex string */
      hash: string
/** Human Readable Part of Payment Request string */
      hrp: string
/** Signature Hash Preimage Hex string */
      preimage: string
/** Data Tag number */
      tags: number
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
/** Unauthenticated LND */
      lnd: LND
/** AEZSeed Encryption Passphrase string */
      passphrase?: string
/** Wallet Password string */
      password: string
/** Seed Mnemonic string */
      seed: string
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
/** Authenticated LND */
      lnd: LND
/** BOLT 11 Payment Request string */
      request: string
    }

    @returns via cbk or Promise
    {
/** Fallback Chain Address string */
      chain_address: string
/** Final CLTV Delta number */
      cltv_delta?: number
/** Payment Description string */
      description: string
/** Payment Longer Description Hash string */
      description_hash: string
/** Public Key string */
      destination: string
/** ISO 8601 Date string */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required To Pay boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Payment Hash string */
      id: string
/** Requested Millitokens string */
      mtokens: string
/** Payment Identifier Hex Encoded string */
      payment?: string
      routes: [[{
/** Base Routing Fee In Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Requested Tokens Rounded Up number */
      safe_tokens: number
/** Requested Tokens Rounded Down number */
      tokens: number
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
/** Authenticated LND */
      lnd: LND
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
/** Authenticated LND */
      lnd: LND
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
/** Key Family number */
      key_family?: number
/** Key Index number */
      key_index?: number
/** Authenticated LND */
      lnd: LND
/** Public Key Hex string */
      partner_public_key: string
    }

    @returns via cbk or Promise
    {
/** Shared Secret Hex string */
      secret: string
    }

### disconnectWatchtower

Disconnect a watchtower

Requires LND built with `wtclientrpc` build tag

Requires `offchain:write` permission

    {
/** Authenticated LND */
      lnd: LND
/** Watchtower Public Key Hex string */
      public_key: string
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
/** Pending Channel Id Hex string */
      channels: string
/** Signed Funding Transaction PSBT Hex string */
      funding: string
/** Authenticated LND */
      lnd: LND
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
/** Chain Fee Tokens Per Virtual Byte number */
      fee_tokens_per_vbyte?: number
      inputs?: [{
/** Unspent Transaction Id Hex string */
        transaction_id: string
/** Unspent Transaction Output Index number */
        transaction_vout: number
      }]
/** Authenticated LND */
      lnd: LND
      outputs?: [{
/** Chain Address string */
        address: string
/** Send Tokens Tokens number */
        tokens: number
      }]
/** Confirmations To Wait number */
      target_confirmations?: number
/** Existing PSBT Hex string */
      psbt?: string
    }

    @returns via cbk or Promise
    {
      inputs: [{
/** UTXO Lock Expires At ISO 8601 Date string */
        lock_expires_at?: string
/** UTXO Lock Id Hex string */
        lock_id?: string
/** Unspent Transaction Id Hex string */
        transaction_id: string
/** Unspent Transaction Output Index number */
        transaction_vout: number
      }]
      outputs: [{
/** Spends To a Generated Change Output boolean */
        is_change: boolean
/** Output Script Hex string */
        output_script: string
/** Send Tokens Tokens number */
        tokens: number
      }]
/** Unsigned PSBT Hex string */
      psbt: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Root Access Id number */
      ids: number
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
/** Authenticated LND */
      lnd: LND
/** Get Score For Public Key Hex string */
      node_scores]: [string
    }

    @returns via cbk or Promise
    {
/** Autopilot is Enabled boolean */
      is_enabled: boolean
      nodes: [{
        local_preferential_score: <Local-adjusted Pref Attachment Score number>
        local_score: <Local-adjusted Externally Set Score number>
/** Preferential Attachment Score number */
        preferential_score: number
/** Node Public Key Hex string */
        public_key: string
/** Externally Set Score number */
        score: number
        weighted_local_score: <Combined Weighted Locally-Adjusted Score number>
/** Combined Weighted Score number */
        weighted_score: number
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
/** Authenticated LND */
      lnd: LND
/** Funding Transaction Id Hex string */
      transaction_id: string
/** Funding Transaction Output Index number */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Channel Backup Hex string */
      backup: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** All Channels Backup Hex string */
      backup: string
      channels: {
/** Individualized Channel Backup Hex string */
        backup: string
/** Channel Funding Transaction Id Hex string */
        transaction_id: string
/** Channel Funding Transaction Output Index number */
        transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Confirmed Chain Balance Tokens number */
      chain_balance: number
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
/** Authenticated LND */
      lnd: LND
      send_to: [{
/** Address string */
        address: string
/** Tokens number */
        tokens: number
      }]
/** Target Confirmations number */
      target_confirmations?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens number */
      fee: number
/** Fee Tokens Per VByte number */
      tokens_per_vbyte: number
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
/** Future Blocks Confirmation number */
      confirmation_target?: number
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Tokens Per Virtual Byte number */
      tokens_per_vbyte: number
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
/** Confirmed After Current Best Chain Block Height number */
      after?: number
/** Confirmed Before Current Best Chain Block Height number */
      before?: number
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      transactions: [{
/** Block Hash string */
        block_id?: string
/** Confirmation Count number */
        confirmation_count?: number
/** Confirmation Block Height number */
        confirmation_height?: number
/** Created ISO 8601 Date string */
        created_at: string
/** Transaction Label string */
        description?: string
/** Fees Paid Tokens number */
        fee?: number
/** Transaction Id string */
        id: string
/** Is Confirmed boolean */
        is_confirmed: boolean
/** Transaction Outbound boolean */
        is_outgoing: boolean
/** Address string */
        output_addresses: string
/** Tokens Including Fee number */
        tokens: number
/** Raw Transaction Hex string */
        transaction?: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Channels Balance Tokens number */
      channel_balance: number
/** Channels Balance Millitokens string */
      channel_balance_mtokens?: string
/** Inbound Liquidity Tokens number */
      inbound?: number
/** Inbound Liquidity Millitokens string */
      inbound_mtokens?: string
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
/** Standard Format Channel Id string */
      id: string
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Maximum Tokens number */
      capacity: number
/** Standard Format Channel Id string */
      id: string
      policies: [{
/** Base Fee Millitokens string */
        base_fee_mtokens?: string
/** Locktime Delta number */
        cltv_delta?: number
/** Fees Charged Per Million Millitokens number */
        fee_rate?: number
/** Channel Is Disabled boolean */
        is_disabled?: boolean
/** Maximum HTLC Millitokens Value string */
        max_htlc_mtokens?: string
/** Minimum HTLC Millitokens Value string */
        min_htlc_mtokens?: string
/** Node Public Key string */
        public_key: string
/** Policy Last Updated At ISO 8601 Date string */
        updated_at?: string
      }]
/** Transaction Id Hex string */
      transaction_id: string
/** Transaction Output Index number */
      transaction_vout: number
/** Last Update Epoch ISO 8601 Date string */
      updated_at?: string
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
/** Limit Results To Only Active Channels boolean */
      is_active?: boolean
/** Limit Results To Only Offline Channels boolean */
      is_offline?: boolean
/** Limit Results To Only Private Channels boolean */
      is_private?: boolean
/** Limit Results To Only Public Channels boolean */
      is_public?: boolean
/** Authenticated LND */
      lnd: LND
/** Only Channels With Public Key Hex string */
      partner_public_key?: string
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Channel Token Capacity number */
        capacity: number
/** Commit Transaction Fee number */
        commit_transaction_fee: number
/** Commit Transaction Weight number */
        commit_transaction_weight: number
/** Coop Close Restricted to Address string */
        cooperative_close_address?: string
/** Prevent Coop Close Until Height number */
        cooperative_close_delay_height?: number
/** Standard Format Channel Id string */
        id: string
/** Channel Active boolean */
        is_active: boolean
/** Channel Is Closing boolean */
        is_closing: boolean
/** Channel Is Opening boolean */
        is_opening: boolean
/** Channel Partner Opened Channel boolean */
        is_partner_initiated: boolean
/** Channel Is Private boolean */
        is_private: boolean
/** Remote Key Is Static boolean */
        is_static_remote_key: boolean
/** Local Balance Tokens number */
        local_balance: number
/** Local CSV Blocks Delay number */
        local_csv?: number
        local_dust?: <Remote Non-Enforceable Amount Tokens number>
/** Local Initially Pushed Tokens number */
        local_given?: number
/** Local Maximum Attached HTLCs number */
        local_max_htlcs?: number
/** Local Maximum Pending Millitokens string */
        local_max_pending_mtokens?: string
/** Local Minimum HTLC Millitokens string */
        local_min_htlc_mtokens?: string
/** Local Reserved Tokens number */
        local_reserve: number
/** Channel Partner Public Key string */
        partner_public_key: string
        pending_payments: [{
/** Payment Preimage Hash Hex string */
          id: string
/** Forward Inbound From Channel Id string */
          in_channel?: string
/** Payment Index on Inbound Channel number */
          in_payment?: number
/** Payment is a Forward boolean */
          is_forward?: boolean
/** Payment Is Outgoing boolean */
          is_outgoing: boolean
/** Forward Outbound To Channel Id string */
          out_channel?: string
/** Payment Index on Outbound Channel number */
          out_payment?: number
/** Payment Attempt Id number */
          payment?: number
/** Chain Height Expiration number */
          timeout: number
/** Payment Tokens number */
          tokens: number
        }]
/** Received Tokens number */
        received: number
/** Remote Balance Tokens number */
        remote_balance: number
/** Remote CSV Blocks Delay number */
        remote_csv?: number
        remote_dust?: <Remote Non-Enforceable Amount Tokens number>
/** Remote Initially Pushed Tokens number */
        remote_given?: number
/** Remote Maximum Attached HTLCs number */
        remote_max_htlcs?: number
/** Remote Maximum Pending Millitokens string */
        remote_max_pending_mtokens?: string
/** Remote Minimum HTLC Millitokens string */
        remote_min_htlc_mtokens?: string
/** Remote Reserved Tokens number */
        remote_reserve: number
/** Sent Tokens number */
        sent: number
/** Monitoring Uptime Channel Down Milliseconds number */
        time_offline?: number
/** Monitoring Uptime Channel Up Milliseconds number */
        time_online?: number
/** Blockchain Transaction Id string */
        transaction_id: string
/** Blockchain Transaction Vout number */
        transaction_vout: number
/** Unsettled Balance Tokens number */
        unsettled_balance: number
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
/** Only Return Breach Close Channels boolean */
      is_breach_close?: boolean
/** Only Return Cooperative Close Channels boolean */
      is_cooperative_close?: boolean
/** Only Return Funding Canceled Channels boolean */
      is_funding_cancel?: boolean
/** Only Return Local Force Close Channels boolean */
      is_local_force_close?: boolean
/** Only Return Remote Force Close Channels boolean */
      is_remote_force_close?: boolean
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Closed Channel Capacity Tokens number */
        capacity: number
/** Channel Balance Output Spent By Tx Id string */
        close_balance_spent_by?: string
/** Channel Balance Close Tx Output Index number */
        close_balance_vout?: number
        close_payments: [{
/** Payment Is Outgoing boolean */
          is_outgoing: boolean
/** Payment Is Claimed With Preimage boolean */
          is_paid: boolean
/** Payment Resolution Is Pending boolean */
          is_pending: boolean
/** Payment Timed Out And Went Back To Payer boolean */
          is_refunded: boolean
/** Close Transaction Spent By Transaction Id Hex string */
          spent_by?: string
/** Associated Tokens number */
          tokens: number
/** Transaction Id Hex string */
          transaction_id: string
/** Transaction Output Index number */
          transaction_vout: number
        }]
/** Channel Close Confirmation Height number */
        close_confirm_height?: number
/** Closing Transaction Id Hex string */
        close_transaction_id?: string
/** Channel Close Final Local Balance Tokens number */
        final_local_balance: number
/** Closed Channel Timelocked Tokens number */
        final_time_locked_balance: number
/** Closed Standard Format Channel Id string */
        id?: string
/** Is Breach Close boolean */
        is_breach_close: boolean
/** Is Cooperative Close boolean */
        is_cooperative_close: boolean
/** Is Funding Cancelled Close boolean */
        is_funding_cancel: boolean
/** Is Local Force Close boolean */
        is_local_force_close: boolean
/** Channel Was Closed By Channel Peer boolean */
        is_partner_closed?: boolean
/** Channel Was Initiated By Channel Peer boolean */
        is_partner_initiated?: boolean
/** Is Remote Force Close boolean */
        is_remote_force_close: boolean
/** Partner Public Key Hex string */
        partner_public_key: string
/** Channel Funding Transaction Id Hex string */
        transaction_id: string
/** Channel Funding Output Index number */
        transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Maximum Updates Per Session number */
      max_session_update_count: number
/** Sweep Tokens per Virtual Byte number */
      sweep_tokens_per_vbyte: number
/** Total Backups Made Count number */
      backups_count: number
/** Total Backup Failures Count number */
      failed_backups_count: number
/** Finished Updated Sessions Count number */
      finished_sessions_count: number
/** As Yet Unacknowledged Backup Requests Count number */
      pending_backups_count: number
/** Total Backup Sessions Starts Count number */
      sessions_count: number
      towers: [{
/** Tower Can Be Used For New Sessions boolean */
        is_active: boolean
/** Identity Public Key Hex string */
        public_key: string
        sessions: [{
/** Total Successful Backups Made Count number */
          backups_count: number
/** Backups Limit number */
          max_backups_count: number
/** Backups Pending Acknowledgement Count number */
          pending_backups_count: number
/** Fee Rate in Tokens Per Virtual Byte number */
          sweep_tokens_per_vbyte: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Base Flat Fee Tokens Rounded Up number */
        base_fee: number
/** Base Flat Fee Millitokens string */
        base_fee_mtokens: string
/** Standard Format Channel Id string */
        id: string
/** Channel Funding Transaction Id Hex string */
        transaction_id: string
/** Funding Outpoint Output Index number */
        transaction_vout: number
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
/** From Public Key Hex string */
      from: string
/** Authenticated LND */
      lnd: LND
/** Millitokens To Send string */
      mtokens: string
/** To Public Key Hex string */
      to: string
    }

    @returns via cbk or Promise
    {
/** Success Confidence Score Out Of One Million number */
      confidence: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      nodes: [{
        peers: [{
/** Failed to Forward Tokens number */
          failed_tokens?: number
/** Forwarded Tokens number */
          forwarded_tokens?: number
          last_failed_forward_at?: <Failed Forward At ISO-8601 Date string>
/** Forwarded At ISO 8601 Date string */
          last_forward_at?: string
/** To Public Key Hex string */
          to_public_key: string
        }]
/** Node Identity Public Key Hex string */
        public_key: string
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
/** Get Only Payments Forwarded At Or After ISO 8601 Date string */
      after?: string
/** Get Only Payments Forwarded Before ISO 8601 Date string */
      before?: string
/** Page Result Limit number */
      limit?: number
/** Authenticated LND */
      lnd: LND
/** Opaque Paging Token string */
      token?: string
    }

    @returns via cbk or Promise
    {
      forwards: [{
/** Forward Record Created At ISO 8601 Date string */
        created_at: string
/** Fee Tokens Charged number */
        fee: number
/** Approximated Fee Millitokens Charged string */
        fee_mtokens: string
/** Incoming Standard Format Channel Id string */
        incoming_channel: string
/** Forwarded Millitokens string */
        mtokens: string
/** Outgoing Standard Format Channel Id string */
        outgoing_channel: string
/** Forwarded Tokens number */
        tokens: number
      }]
/** Contine With Opaque Paging Token string */
      next?: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Best Chain Hash Hex string */
      current_block_hash: string
/** Best Chain Height number */
      current_block_height: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Node Identity Public Key Hex string */
      public_key: string
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
/** Payment Hash Id Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Fallback Chain Address string */
      chain_address?: string
/** CLTV Delta number */
      cltv_delta: number
/** Settled at ISO 8601 Date string */
      confirmed_at?: string
/** ISO 8601 Date string */
      created_at: string
/** Description string */
      description: string
/** Description Hash Hex string */
      description_hash?: string
/** ISO 8601 Date string */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required To Pay boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Payment Hash string */
      id: string
/** Invoice is Canceled boolean */
      is_canceled?: boolean
/** Invoice is Confirmed boolean */
      is_confirmed: boolean
/** HTLC is Held boolean */
      is_held?: boolean
/** Invoice is Private boolean */
      is_private: boolean
/** Invoice is Push Payment boolean */
      is_push?: boolean
      payments: [{
/** Payment Settled At ISO 8601 Date string */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date string */
        created_at: string
/** Payment Held Since Block Height number */
        created_height: number
/** Incoming Payment Through Channel Id string */
        in_channel: string
/** Payment is Canceled boolean */
        is_canceled: boolean
/** Payment is Confirmed boolean */
        is_confirmed: boolean
/** Payment is Held boolean */
        is_held: boolean
        messages: [{
/** Message Type number string */
          type: string
/** Raw Value Hex string */
          value: string
        }]
/** Incoming Payment Millitokens string */
        mtokens: string
/** Pending Payment Channel HTLC Index number */
        pending_index?: number
/** Payment Tokens number */
        tokens: number
      }]
/** Received Tokens number */
      received: number
/** Received Millitokens string */
      received_mtokens: string
/** Bolt 11 Invoice string */
      request?: string
/** Secret Preimage Hex string */
      secret: string
/** Tokens number */
      tokens: number
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
/** Page Result Limit number */
      limit?: number
/** Authenticated LND */
      lnd: LND
/** Opaque Paging Token string */
      token?: string
    }

    @returns via cbk or Promise
    {
      invoices: [{
/** Fallback Chain Address string */
        chain_address?: string
/** Settled at ISO 8601 Date string */
        confirmed_at?: string
/** ISO 8601 Date string */
        created_at: string
/** Description string */
        description: string
/** Description Hash Hex string */
        description_hash?: string
/** ISO 8601 Date string */
        expires_at: string
        features: [{
/** BOLT 09 Feature Bit number */
          bit: number
/** Feature is Known boolean */
          is_known: boolean
/** Feature Support is Required To Pay boolean */
          is_required: boolean
/** Feature Type string */
          type: string
        }]
/** Payment Hash string */
        id: string
/** Invoice is Canceled boolean */
        is_canceled?: boolean
/** Invoice is Confirmed boolean */
        is_confirmed: boolean
/** HTLC is Held boolean */
        is_held?: boolean
/** Invoice is Private boolean */
        is_private: boolean
/** Invoice is Push Payment boolean */
        is_push?: boolean
        payments: [{
/** Payment Settled At ISO 8601 Date string */
          confirmed_at?: string
/** Payment Held Since ISO 860 Date string */
          created_at: string
/** Payment Held Since Block Height number */
          created_height: number
/** Incoming Payment Through Channel Id string */
          in_channel: string
/** Payment is Canceled boolean */
          is_canceled: boolean
/** Payment is Confirmed boolean */
          is_confirmed: boolean
/** Payment is Held boolean */
          is_held: boolean
          messages: [{
/** Message Type number string */
            type: string
/** Raw Value Hex string */
            value: string
          }]
/** Incoming Payment Millitokens string */
          mtokens: string
/** Pending Payment Channel HTLC Index number */
          pending_index?: number
/** Payment Tokens number */
          tokens: number
/** Total Millitokens string */
          total_mtokens?: string
        }]
/** Received Tokens number */
        received: number
/** Received Millitokens string */
        received_mtokens: string
/** Bolt 11 Invoice string */
        request?: string
/** Secret Preimage Hex string */
        secret: string
/** Tokens number */
        tokens: number
      }]
/** Next Opaque Paging Token string */
      next?: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      methods: [{
/** Method Endpoint Path string */
        endpoint: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      nodes: [{
/** Betweenness Centrality number */
        betweenness: number
/** Normalized Betweenness Centrality number */
        betweenness_normalized: number
/** Node Public Key Hex string */
        public_key: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Channel Capacity Tokens number */
        capacity: number
/** Standard Format Channel Id string */
        id: string
        policies: [{
/** Bae Fee Millitokens string */
          base_fee_mtokens?: string
/** CLTV Height Delta number */
          cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
          fee_rate?: number
/** Edge is Disabled boolean */
          is_disabled?: boolean
/** Maximum HTLC Millitokens string */
          max_htlc_mtokens?: string
/** Minimum HTLC Millitokens string */
          min_htlc_mtokens?: string
/** Public Key string */
          public_key: string
/** Last Update Epoch ISO 8601 Date string */
          updated_at?: string
        }]
/** Funding Transaction Id string */
        transaction_id: string
/** Funding Transaction Output Index number */
        transaction_vout: number
/** Last Update Epoch ISO 8601 Date string */
        updated_at?: string
      }]
      nodes: [{
/** Name string */
        alias: string
/** Hex Encoded Color string */
        color: string
        features: [{
/** BOLT 09 Feature Bit number */
          bit: number
/** Feature is Known boolean */
          is_known: boolean
/** Feature Support is Required boolean */
          is_required: boolean
/** Feature Type string */
          type: string
        }]
/** Node Public Key string */
        public_key: string
/** Network Address and Port string */
        sockets: string
/** Last Updated ISO 8601 Date string */
        updated_at: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Tokens number */
      average_channel_size: number
/** Channels Count number */
      channel_count: number
/** Tokens number */
      max_channel_size: number
/** Median Channel Tokens number */
      median_channel_size: number
/** Tokens number */
      min_channel_size: number
/** Node Count number */
      node_count: number
/** Channel Edge Count number */
      not_recently_updated_policy_count: number
/** Total Capacity number */
      total_capacity: number
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
/** Omit Channels from Node boolean */
      is_omitting_channels?: boolean
/** Authenticated LND */
      lnd: LND
/** Node Public Key Hex string */
      public_key: string
    }

    @returns via cbk or Promise
    {
/** Node Alias string */
      alias: string
/** Node Total Capacity Tokens number */
      capacity: number
/** Known Node Channels number */
      channel_count: number
      channels?: [{
/** Maximum Tokens number */
        capacity: number
/** Standard Format Channel Id string */
        id: string
        policies: [{
/** Base Fee Millitokens string */
          base_fee_mtokens?: string
/** Locktime Delta number */
          cltv_delta?: number
/** Fees Charged Per Million Millitokens number */
          fee_rate?: number
/** Channel Is Disabled boolean */
          is_disabled?: boolean
/** Maximum HTLC Millitokens Value string */
          max_htlc_mtokens?: string
/** Minimum HTLC Millitokens Value string */
          min_htlc_mtokens?: string
/** Node Public Key string */
          public_key: string
/** Policy Last Updated At ISO 8601 Date string */
          updated_at?: string
        }]
/** Transaction Id Hex string */
        transaction_id: string
/** Transaction Output Index number */
        transaction_vout: number
/** Channel Last Updated At ISO 8601 Date string */
        updated_at?: string
      }]
/** RGB Hex Color string */
      color: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
      sockets: [{
/** Host and Port string */
        socket: string
/** Socket Type string */
        type: string
      }]
/** Last Known Update ISO 8601 Date string */
      updated_at?: string
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
/** Payment Preimage Hash Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      failed?: {
/** Failed Due To Lack of Balance boolean */
        is_insufficient_balance: boolean
/** Failed Due to Payment Rejected At Destination boolean */
        is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout boolean */
        is_pathfinding_timeout: boolean
/** Failed Due to Absence of Path Through Graph boolean */
        is_route_not_found: boolean
      }
/** Payment Is Settled boolean */
      is_confirmed?: boolean
/** Payment Is Failed boolean */
      is_failed?: boolean
/** Payment Is Pending boolean */
      is_pending?: boolean
      payment?: {
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Routing Fee Tokens number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forwarded Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
/** Payment Hash Hex string */
        id: string
/** Total Millitokens Paid string */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Tokens Rounded Up number */
        safe_tokens: number
/** Payment Preimage Hex string */
        secret: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens Paid number */
        tokens: number
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
/** Page Result Limit number */
      limit?: number
/** Authenticated LND */
      lnd: LND
/** Opaque Paging Token string */
      token?: string
    }

    @returns via cbk or Promise
    {
      payments: [{
        attempts: [{
          failure?: {
/** Error Type Code number */
            code: number
            details?: {
/** Standard Format Channel Id string */
              channel?: string
/** Error Associated Block Height number */
              height?: number
/** Failed Hop Index number */
              index?: number
/** Error Millitokens string */
              mtokens?: string
              policy?: {
/** Base Fee Millitokens string */
                base_fee_mtokens: string
/** Locktime Delta number */
                cltv_delta: number
/** Fees Charged Per Million Tokens number */
                fee_rate: number
/** Channel is Disabled boolean */
                is_disabled?: boolean
/** Maximum HLTC Millitokens Value string */
                max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value string */
                min_htlc_mtokens: string
/** Updated At ISO 8601 Date string */
                updated_at: string
              }
/** Error CLTV Timeout Height number */
              timeout_height?: number
              update?: {
/** Chain Id Hex string */
                chain: string
/** Channel Flags number */
                channel_flags: number
/** Extra Opaque Data Hex string */
                extra_opaque_data: string
/** Message Flags number */
                message_flags: number
/** Channel Update Signature Hex string */
                signature: string
              }
            }
/** Error Message string */
            message: string
          }
/** Payment Attempt Succeeded boolean */
          is_confirmed: boolean
/** Payment Attempt Failed boolean */
          is_failed: boolean
/** Payment Attempt is Waiting For Resolution boolean */
          is_pending: boolean
          route: {
/** Route Fee Tokens number */
            fee: number
/** Route Fee Millitokens string */
            fee_mtokens: string
            hops: [{
/** Standard Format Channel Id string */
              channel: string
/** Channel Capacity Tokens number */
              channel_capacity: number
/** Fee number */
              fee: number
/** Fee Millitokens string */
              fee_mtokens: string
/** Forward Tokens number */
              forward: number
/** Forward Millitokens string */
              forward_mtokens: string
/** Forward Edge Public Key Hex string */
              public_key?: string
/** Timeout Block Height number */
              timeout?: number
            }]
            mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex string */
            payment?: string
/** Timeout Block Height number */
            timeout: number
            tokens: <Total Fee-Inclusive Tokens number>
/** Total Millitokens string */
            total_mtokens?: string
          }
        }]
        created_at: <Payment at ISO-8601 Date string>
/** Destination Node Public Key Hex string */
        destination: string
/** Paid Routing Fee Rounded Down Tokens number */
        fee: number
/** Paid Routing Fee in Millitokens string */
        fee_mtokens: string
/** First Route Hop Public Key Hex string */
        hops: string
/** Payment Preimage Hash string */
        id: string
/** Payment Add Index number */
        index?: number
/** Payment is Confirmed boolean */
        is_confirmed: boolean
/** Transaction Is Outgoing boolean */
        is_outgoing: boolean
/** Millitokens Sent to Destination string */
        mtokens: string
/** BOLT 11 Payment Request string */
        request?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Tokens Rounded Up number */
        safe_tokens: number
/** Payment Preimage Hex string */
        secret: string
/** Rounded Down Tokens Sent to Destination number */
        tokens: number
      }]
/** Next Opaque Paging Token string */
      next?: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      peers: [{
/** Bytes Received number */
        bytes_received: number
/** Bytes Sent number */
        bytes_sent: number
        features: [{
/** BOLT 09 Feature Bit number */
          bit: number
/** Feature is Known boolean */
          is_known: boolean
/** Feature Support is Required boolean */
          is_required: boolean
/** Feature Type string */
          type: string
        }]
/** Is Inbound Peer boolean */
        is_inbound: boolean
/** Is Syncing Graph Data boolean */
        is_sync_peer?: boolean
/** Peer Last Reconnected At ISO 8601 Date string */
        last_reconnected?: string
/** Ping Latency Milliseconds number */
        ping_time: number
/** Node Identity Public Key string */
        public_key: string
/** Count of Reconnections Over Time number */
        reconnection_rate?: number
/** Network Address And Port string */
        socket: string
/** Amount Received Tokens number */
        tokens_received: number
/** Amount Sent Tokens number */
        tokens_sent: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Pending Chain Balance Tokens number */
      pending_chain_balance: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      pending_channels: [{
/** Channel Closing Transaction Id string */
        close_transaction_id?: string
/** Channel Is Active boolean */
        is_active: boolean
/** Channel Is Closing boolean */
        is_closing: boolean
/** Channel Is Opening boolean */
        is_opening: boolean
/** Channel Partner Initiated Channel boolean */
        is_partner_initiated?: boolean
/** Channel Local Tokens Balance number */
        local_balance: number
/** Channel Local Reserved Tokens number */
        local_reserve: number
/** Channel Peer Public Key string */
        partner_public_key: string
/** Tokens Pending Recovery number */
        pending_balance?: number
        pending_payments?: [{
/** Payment Is Incoming boolean */
          is_incoming: boolean
/** Payment Timelocked Until Height number */
          timelock_height: number
/** Payment Tokens number */
          tokens: number
/** Payment Transaction Id string */
          transaction_id: string
/** Payment Transaction Vout number */
          transaction_vout: number
        }]
/** Tokens Received number */
        received: number
/** Tokens Recovered From Close number */
        recovered_tokens?: number
/** Remote Tokens Balance number */
        remote_balance: number
/** Channel Remote Reserved Tokens number */
        remote_reserve: number
/** Send Tokens number */
        sent: number
/** Pending Tokens Block Height Timelock number */
        timelock_expiration?: number
/** Funding Transaction Fee Tokens number */
        transaction_fee?: number
/** Channel Funding Transaction Id string */
        transaction_id: string
/** Channel Funding Transaction Vout number */
        transaction_vout: number
/** Funding Transaction Weight number */
        transaction_weight?: number
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
/** Key Family number */
      family: number
/** Key Index number */
      index?: number
/** Authenticated API LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Key Index number */
      index: number
/** Public Key Hex string */
      public_key: string
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
/** Starting Hex Serialized Public Key */
      from?: Key
      hops: [{
/** Forward Millitokens string */
        forward_mtokens: string
/** Forward Edge Public Key Hex string */
        public_key: string
      }]
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Confidence Score Out Of One Million number */
      confidence: number
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Authenticated LND */
      lnd: LND
/** Millitokens to Send string */
      mtokens?: string
/** Outgoing Channel Id string */
      outgoing_channel?: string
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Payment Identifier Hex string */
      payment?: string
/** Public Key Hex string */
      public_keys: string
/** Tokens to Send number */
      tokens?: number
/** Payment Total Millitokens string */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route: {
/** Route Fee Tokens number */
        fee: number
/** Route Fee Millitokens string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Forward Edge Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex string */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Tokens Rounded Up number */
        safe_tokens: number
/** Route Timeout Height number */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens number>
/** Payment Total Millitokens string */
        total_mtokens?: string
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Final Send Destination Hex Encoded Public Key string */
      destination: string
      features?: [{
/** Feature Bit number */
        bit: number
      }]
      ignore?: [{
/** Channel Id string */
        channel?: string
/** Public Key Hex string */
        from_public_key: string
/** To Public Key Hex string */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex string */
      incoming_peer?: string
/** Ignore Past Failures boolean */
      is_ignoring_past_failures?: boolean
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens number */
      max_fee?: number
/** Maximum Fee Millitokens string */
      max_fee_mtokens?: string
/** Max CLTV Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number string */
        type: string
/** Message To Final Destination Raw Value Hex Encoded string */
        value: string
      }]
/** Tokens to Send string */
      mtokens?: string
/** Outgoing Channel Id string */
      outgoing_channel?: string
/** Payment Identifier Hex Strimng */
      payment?: Strimng
      routes?: [[{
/** Base Routing Fee In Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** Channel Capacity Tokens number */
        channel_capacity?: number
/** CLTV Delta Blocks number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Starting Node Public Key Hex string */
      start?: string
/** Tokens number */
      tokens?: number
/** Total Millitokens of Shards string */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route?: {
/** Route Confidence Score Out Of One Million number */
        confidence?: number
/** Route Fee Tokens number */
        fee: number
/** Route Fee Millitokens string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Forward Edge Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Tokens Rounded Up number */
        safe_tokens: number
/** Route Timeout Height number */
        timeout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      transactions: [{
/** Block Hash string */
        block_id?: string
/** Confirmation Count number */
        confirmation_count?: number
/** Confirmation Block Height number */
        confirmation_height?: number
/** Created ISO 8601 Date string */
        created_at: string
/** Fees Paid Tokens number */
        fee?: number
/** Transaction Id string */
        id: string
/** Is Confirmed boolean */
        is_confirmed: boolean
/** Transaction Outbound boolean */
        is_outgoing: boolean
/** Address string */
        output_addresses: string
        spends: [{
/** Output Tokens number */
          tokens?: number
/** Spend Transaction Id Hex string */
          transaction_id: string
/** Spend Transaction Output Index number */
          transaction_vout: number
        }]
/** Tokens Including Fee number */
        tokens: number
/** Raw Transaction Hex string */
        transaction?: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      tower?: {
/** Watchtower Server Public Key Hex string */
        public_key: string
/** Socket string */
        sockets: string
/** Watchtower External URI string */
        uris: string
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
/** Authenticated LND */
      lnd: LND
/** Maximum Confirmations number */
      max_confirmations?: number
/** Minimum Confirmations number */
      min_confirmations?: number
    }

    @returns via cbk or Promise
    {
      utxos: [{
/** Chain Address string */
        address: string
/** Chain Address Format string */
        address_format: string
/** Confirmation Count number */
        confirmation_count: number
/** Output Script Hex string */
        output_script: string
/** Unspent Tokens number */
        tokens: number
/** Transaction Id Hex string */
        transaction_id: string
/** Transaction Output Index number */
        transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Active Channels Count number */
      active_channels_count: number
/** Node Alias string */
      alias: string
/** Chain Id Hex string */
      chains: string
/** Node Color string */
      color: string
/** Best Chain Hash Hex string */
      current_block_hash: string
/** Best Chain Height number */
      current_block_height: number
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Is Synced To Chain boolean */
      is_synced_to_chain: boolean
/** Latest Known Block At Date string */
      latest_block_at: string
/** Peer Count number */
      peers_count: number
/** Pending Channels Count number */
      pending_channels_count: number
/** Public Key string */
      public_key: string
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
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Build Tag string */
      build_tags: string
/** Commit SHA1 160 Bit Hash Hex string */
      commit_hash: string
/** Is Autopilot RPC Enabled boolean */
      is_autopilotrpc_enabled: boolean
/** Is Chain RPC Enabled boolean */
      is_chainrpc_enabled: boolean
/** Is Invoices RPC Enabled boolean */
      is_invoicesrpc_enabled: boolean
/** Is Sign RPC Enabled boolean */
      is_signrpc_enabled: boolean
/** Is Wallet RPC Enabled boolean */
      is_walletrpc_enabled: boolean
/** Is Watchtower Server RPC Enabled boolean */
      is_watchtowerrpc_enabled: boolean
/** Is Watchtower Client RPC Enabled boolean */
      is_wtclientrpc_enabled: boolean
/** Recognized LND Version string */
      version?: string
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
/** Macaroon Id Positive Numeric string */
      id?: string
/** Can Add or Remove Peers boolean */
      is_ok_to_adjust_peers?: boolean
/** Can Make New Addresses boolean */
      is_ok_to_create_chain_addresses?: boolean
/** Can Create Lightning Invoices boolean */
      is_ok_to_create_invoices?: boolean
/** Can Create Macaroons boolean */
      is_ok_to_create_macaroons?: boolean
/** Can Derive Public Keys boolean */
      is_ok_to_derive_keys?: boolean
/** Can List Access Ids boolean */
      is_ok_to_get_access_ids?: boolean
/** Can See Chain Transactions boolean */
      is_ok_to_get_chain_transactions?: boolean
/** Can See Invoices boolean */
      is_ok_to_get_invoices?: boolean
/** Can General Graph and Wallet Information boolean */
      is_ok_to_get_wallet_info?: boolean
/** Can Get Historical Lightning Transactions boolean */
      is_ok_to_get_payments?: boolean
/** Can Get Node Peers Information boolean */
      is_ok_to_get_peers?: boolean
/** Can Send Funds or Edit Lightning Payments boolean */
      is_ok_to_pay?: boolean
/** Can Revoke Access Ids boolean */
      is_ok_to_revoke_access_ids?: boolean
/** Can Send Coins On Chain boolean */
      is_ok_to_send_to_chain_addresses?: boolean
/** Can Sign Bytes From Node Keys boolean */
      is_ok_to_sign_bytes?: boolean
/** Can Sign Messages From Node Key boolean */
      is_ok_to_sign_messages?: boolean
/** Can Terminate Node or Change Operation Mode boolean */
      is_ok_to_stop_daemon?: boolean
/** Can Verify Signatures of Bytes boolean */
      is_ok_to_verify_bytes_signatures?: boolean
/** Can Verify Messages From Node Keys boolean */
      is_ok_to_verify_messages?: boolean
/** Authenticated LND */
      lnd: LND
      permissions]: [<Entity:Action string>?
    }

    @returns via cbk or Promise
    {
/** Base64 Encoded Macaroon string */
      macaroon: string
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
/** Bind to Address string */
      bind?: string
/** LND Cert Base64 string */
      cert?: string
/** Log Function */
      log: Function
/** Router Path string */
      path: string
/** Listen Port number */
      port: number
/** LND Socket string */
      socket: string
/** Log Write Stream Object */
      stream: Object
    }

    @returns
    {
/** Express Application Object */
      app: Object
/** Web Server Object */
      server: Object
/** WebSocket Server Object */
      wss: Object
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Pay to Node with Public Key Hex string */
      destination: string
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Expiration CLTV Timeout Height number */
      max_timeout_height?: number
/** Pay Out of Outgoing Standard Format Channel Id string */
      outgoing_channel?: string
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
      routes?: [[{
/** Base Routing Fee In Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Paying Tokens number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Payment Is Successfully Tested Within Constraints boolean */
      is_payable: boolean
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
/** Lock Identifier Hex string */
      id?: string
/** Authenticated LND */
      lnd: LND
/** Unspent Transaction Id Hex string */
      transaction_id: string
/** Unspent Transaction Output Index number */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Lock Expires At ISO 8601 Date string */
      expires_at: string
/** Locking Id Hex string */
      id: string
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
/** Chain Fee Tokens Per VByte number */
      chain_fee_tokens_per_vbyte?: number
/** Restrict Cooperative Close To Address string */
      cooperative_close_address?: string
/** Tokens to Gift To Partner number */
      give_tokens?: number
/** Channel is Private boolean */
      is_private?: boolean
/** Authenticated LND */
      lnd: LND
/** Local Tokens number */
      local_tokens: number
/** Spend UTXOs With Minimum Confirmations number */
      min_confirmations?: number
/** Minimum HTLC Millitokens string */
      min_htlc_mtokens?: string
/** Public Key Hex string */
      partner_public_key: string
/** Peer Output CSV Delay number */
      partner_csv_delay?: number
      partner_socket?: <Peer Connection Host:Port string>
    }

    @returns via cbk or Promise
    {
/** Funding Transaction Id string */
      transaction_id: string
/** Funding Transaction Output Index number */
      transaction_vout: number
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
/** Channel Capacity Tokens number */
        capacity: number
/** Restrict Coop Close To Address string */
        cooperative_close_address?: string
/** Tokens to Gift To Partner number */
        give_tokens?: number
/** Channel is Private boolean */
        is_private?: boolean
/** Minimum HTLC Millitokens string */
        min_htlc_mtokens?: string
/** Public Key Hex string */
        partner_public_key: string
/** Peer Output CSV Delay number */
        partner_csv_delay?: number
        partner_socket?: <Peer Connection Host:Port string>
      }]
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      pending: [{
/** Address To Send To string */
        address: string
/** Pending Channel Id Hex string */
        id: string
/** Tokens to Send number */
        tokens: number
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
/** BOLT 11 Payment Request string */
      request: string
    }

    @throws
/** ExpectedLnPrefix Error */
    Error
/** ExpectedPaymentHash Error */
    Error
/** ExpectedPaymentRequest Error */
    Error
/** ExpectedValidHrpForPaymentRequest Error */
    Error
/** FailedToParsePaymentRequestDescriptionHash Error */
    Error
/** FailedToParsePaymentRequestFallbackAddress Error */
    Error
/** FailedToParsePaymentRequestPaymentHash Error */
    Error
/** InvalidDescriptionInPaymentRequest Error */
    Error
/** InvalidOrMissingSignature Error */
    Error
/** InvalidPaymentHashByteLength Error */
    Error
/** InvalidPaymentRequestPrefix Error */
    Error
/** UnknownCurrencyCodeInPaymentRequest Error */
    Error

    @returns
    {
/** Chain Address string */
      chain_addresses]: [string
/** CLTV Delta number */
      cltv_delta: number
/** Invoice Creation Date ISO 8601 string */
      created_at: string
/** Description string */
      description?: string
/** Description Hash Hex string */
      description_hash?: string
/** Public Key string */
      destination: string
/** ISO 8601 Date string */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature Support is Required To Pay boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Payment Request Hash string */
      id: string
/** Invoice is Expired boolean */
      is_expired: boolean
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
/** Network Name string */
      network: string
/** Payment Identifier Hex Encoded string */
      payment?: string
      routes?: [[{
/** Base Fee Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** Final CLTV Expiration Blocks Delta number */
        cltv_delta?: number
/** Fee Rate Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Requested Tokens Rounded Up number */
      safe_tokens?: number
/** Requested Chain Tokens number */
      tokens?: number
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
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Additional Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths number */
      max_paths?: number
/** Max CLTV Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Pay Through Outbound Standard Channel Id string */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids string */
      outgoing_channels]: [string
      path?: {
/** Payment Hash Hex string */
        id: string
        routes: [{
/** Total Fee Tokens To Pay number */
          fee: number
/** Total Fee Millitokens To Pay string */
          fee_mtokens: string
          hops: [{
/** Standard Format Channel Id string */
            channel: string
/** Channel Capacity Tokens number */
            channel_capacity: number
/** Fee number */
            fee: number
/** Fee Millitokens string */
            fee_mtokens: string
/** Forward Tokens number */
            forward: number
/** Forward Millitokens string */
            forward_mtokens: string
/** Public Key Hex string */
            public_key?: string
/** Timeout Block Height number */
            timeout: number
          }]
          messages?: [{
/** Message Type number string */
            type: string
/** Message Raw Value Hex Encoded string */
            value: string
          }]
/** Total Millitokens To Pay string */
          mtokens: string
/** Payment Identifier Hex string */
          payment?: string
/** Expiration Block Height number */
          timeout: number
/** Total Tokens To Pay number */
          tokens: number
        }]
      }
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request string */
      request?: string
/** Total Tokens To Pay to Payment Request number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Fee Paid Tokens number */
      fee: number
/** Fee Paid Millitokens string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Hop Channel Capacity Tokens number */
        channel_capacity: number
/** Hop Forward Fee Millitokens string */
        fee_mtokens: string
/** Hop Forwarded Millitokens string */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Is Confirmed boolean */
      is_confirmed: boolean
/** Is Outoing boolean */
      is_outgoing: boolean
/** Total Millitokens Sent string */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Secret Preimage Hex string */
      secret: string
/** Total Tokens Sent number */
      tokens: number
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Destination Public Key string */
      destination: string
      features?: [{
/** Feature Bit number */
        bit: number
      }]
/** Payment Request Hash Hex string */
      id?: string
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths number */
      max_paths?: number
/** Maximum Expiration CLTV Timeout Height number */
      max_timeout_height?: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Pay Out of Outgoing Channel Id string */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids string */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
      routes: [[{
/** Base Routing Fee In Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Tokens To Pay number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens Paid Rounded Down number */
      fee: number
/** Total Fee Millitokens Paid string */
      fee_mtokens: string
      hops: [{
/** First Route Standard Format Channel Id string */
        channel: string
/** First Route Channel Capacity Tokens number */
        channel_capacity: number
/** First Route Fee Tokens Rounded Down number */
        fee: number
/** First Route Fee Millitokens string */
        fee_mtokens: string
/** First Route Forward Millitokens string */
        forward_mtokens: string
/** First Route Public Key Hex string */
        public_key: string
/** First Route Timeout Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Total Millitokens Paid string */
      mtokens: string
      paths: [{
/** Total Fee Millitokens Paid string */
        fee_mtokens: string
        hops: [{
/** First Route Standard Format Channel Id string */
          channel: string
/** First Route Channel Capacity Tokens number */
          channel_capacity: number
/** First Route Fee Tokens Rounded Down number */
          fee: number
/** First Route Fee Millitokens string */
          fee_mtokens: string
/** First Route Forward Millitokens string */
          forward_mtokens: string
/** First Route Public Key Hex string */
          public_key: string
/** First Route Timeout Block Height number */
          timeout: number
        }]
/** Total Millitokens Paid string */
        mtokens: string
      }]
/** Total Fee Tokens Paid Rounded Up number */
      safe_fee: number
      safe_tokens: <Total Tokens Paid, Rounded Up number>
/** Payment Preimage Hex string */
      secret: string
/** Expiration Block Height number */
      timeout: number
/** Total Tokens Paid Rounded Down number */
      tokens: number
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
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths number */
      max_paths?: number
/** Maximum Height of Payment Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Pay Out of Outgoing Channel Id string */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids string */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request string */
      request: string
/** Tokens To Pay number */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens Paid Rounded Down number */
      fee: number
/** Total Fee Millitokens Paid string */
      fee_mtokens: string
      hops: [{
/** First Route Standard Format Channel Id string */
        channel: string
/** First Route Channel Capacity Tokens number */
        channel_capacity: number
/** First Route Fee Tokens Rounded Down number */
        fee: number
/** First Route Fee Millitokens string */
        fee_mtokens: string
/** First Route Forward Millitokens string */
        forward_mtokens: string
/** First Route Public Key Hex string */
        public_key: string
/** First Route Timeout Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Total Millitokens Paid string */
      mtokens: string
      paths: [{
/** Total Fee Millitokens Paid string */
        fee_mtokens: string
        hops: [{
/** First Route Standard Format Channel Id string */
          channel: string
/** First Route Channel Capacity Tokens number */
          channel_capacity: number
/** First Route Fee Tokens Rounded Down number */
          fee: number
/** First Route Fee Millitokens string */
          fee_mtokens: string
/** First Route Forward Millitokens string */
          forward_mtokens: string
/** First Route Public Key Hex string */
          public_key: string
/** First Route Timeout Block Height number */
          timeout: number
        }]
/** Total Millitokens Paid string */
        mtokens: string
      }]
/** Total Fee Tokens Paid Rounded Up number */
      safe_fee: number
      safe_tokens: <Total Tokens Paid, Rounded Up number>
/** Payment Preimage Hex string */
      secret: string
/** Expiration Block Height number */
      timeout: number
/** Total Tokens Paid Rounded Down number */
      tokens: number
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
/** Payment Hash Hex string */
      id?: string
/** Authenticated LND */
      lnd: LND
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
      routes: [{
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key?: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
      }]
    }

    @returns via cbk or Promise
    {
      failures: [[
/** Failure Code number */
        number
/** Failure Code Message string */
        string
/** Failure Code Details Object */
        Object
      ]]
/** Fee Paid Tokens number */
      fee: number
/** Fee Paid Millitokens string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Hop Channel Capacity Tokens number */
        channel_capacity: number
/** Hop Forward Fee Millitokens string */
        fee_mtokens: string
/** Hop Forwarded Millitokens string */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Is Confirmed boolean */
      is_confirmed: boolean
/** Is Outoing boolean */
      is_outgoing: boolean
/** Total Millitokens Sent string */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Secret Preimage Hex string */
      secret: string
/** Total Tokens Sent Rounded Down number */
      tokens: number
    }

    @returns error via cbk or Promise
    [
/** Error Classification Code number */
      number
/** Error Type string */
      string
      {
        failures: [[
/** Failure Code number */
          number
/** Failure Code Message string */
          string
/** Failure Code Details Object */
          Object
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
/** Cooperative Close Relative Delay number */
      cooperative_close_delay?: number
/** Pending Id Hex string */
      id?: string
/** Channel Funding Output Multisig Local Key Index number */
      key_index: number
/** Authenticated LND */
      lnd: LND
/** Channel Funding Partner Multisig Public Key Hex string */
      remote_key: string
/** Funding Output Transaction Id Hex string */
      transaction_id: string
/** Funding Output Transaction Output Index number */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Pending Channel Id Hex string */
      id: string
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Destination Public Key Hex string */
      destination: string
      features?: [{
/** Feature Bit number */
        bit: number
      }]
      ignore?: [{
/** Channel Id string */
        channel?: string
/** Public Key Hex string */
        from_public_key: string
/** To Public Key Hex string */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex string */
      incoming_peer?: string
/** Adjust Probe For Past Routing Failures boolean */
      is_ignoring_past_failures?: boolean
/** Only Route Through Specified Paths boolean */
      is_strict_hints?: boolean
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Height of Payment Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number string */
        type: string
/** Message To Final Destination Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Outgoing Channel Id string */
      outgoing_channel?: string
/** Time to Spend On A Path Milliseconds number */
      path_timeout_ms?: number
/** Payment Identifier Hex string */
      payment?: string
/** Probe Timeout Milliseconds number */
      probe_timeout_ms?: number
      routes?: [[{
/** Base Routing Fee In Millitokens number */
        base_fee_mtokens?: number
/** Channel Capacity Tokens number */
        channel_capacity?: number
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Tokens number */
      tokens: number
/** Total Millitokens Across Paths string */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route?: {
/** Route Confidence Score Out Of One Million number */
        confidence?: number
/** Route Fee Tokens Rounded Down number */
        fee: number
/** Route Fee Millitokens string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Forward Edge Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex string */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Tokens Rounded Up number */
        safe_tokens: number
/** Timeout Block Height number */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens Rounded Down number>
/** Total Millitokens string */
        total_mtokens?: string
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
/** Channel Capacity Tokens number */
      capacity: number
/** Restrict Cooperative Close To Address string */
      cooperative_close_address?: string
/** Cooperative Close Relative Delay number */
      cooperative_close_delay?: number
/** Tokens to Gift To Partner number */
      give_tokens?: number
/** Pending Channel Id Hex string */
      id: string
/** Channel is Private boolean */
      is_private?: boolean
/** Channel Funding Output MultiSig Local Key Index number */
      key_index: number
/** Authenticated LND */
      lnd: LND
/** Public Key Hex string */
      partner_public_key: string
/** Channel Funding Partner MultiSig Public Key Hex string */
      remote_key: string
/** Funding Output Transaction Id Hex string */
      transaction_id: string
/** Funding Output Transaction Output Index number */
      transaction_vout: number
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
/** Backup Hex string */
      backup: string
/** Authenticated LND */
      lnd: LND
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
/** Backup Hex string */
      backup: string
/** Authenticated LND */
      lnd: LND
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
/** Authenticated LND */
      lnd: LND
/** Public Key Hex string */
      public_key: string
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
/** Expires At ISO 8601 Date string */
      expires_at?: string
/** IP Address string */
      ip?: string
/** Base64 Encoded Macaroon string */
      macaroon: string
    }

    @throws
    <Error>

    @returns
    {
/** Restricted Base64 Encoded Macaroon string */
      macaroon: string
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
/** Access Token Macaroon Root Id Positive Integer string */
      id: string
/** Authenticated LND */
      lnd: LND
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
/** Maximum Tokens number */
        capacity: number
/** Next Node Public Key Hex string */
        destination?: string
/** Standard Format Channel Id string */
        id: string
        policies: [{
/** Base Fee Millitokens string */
          base_fee_mtokens: string
/** Locktime Delta number */
          cltv_delta: number
/** Fees Charged Per Million Tokens number */
          fee_rate: number
/** Channel Is Disabled boolean */
          is_disabled: boolean
/** Minimum HTLC Millitokens Value string */
          min_htlc_mtokens: string
/** Node Public Key string */
          public_key: string
        }]
      }]
/** Final CLTV Delta number */
      cltv_delta?: number
/** Destination Public Key Hex string */
      destination?: string
/** Current Block Height number */
      height: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens To Send string */
      mtokens: string
/** Payment Identification Value Hex string */
      payment?: string
/** Sum of Shards Millitokens string */
      total_mtokens?: string
    }

    @throws
    <Error>

    @returns
    {
      route: {
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key?: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identification Value Hex string */
        payment?: string
/** Timeout Block Height number */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens number>
/** Sum of Shards Millitokens string */
        total_mtokens?: string
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
/** Destination Chain Address string */
      address: string
/** Transaction Label string */
      description?: string
/** Chain Fee Tokens Per Virtual Byte number */
      fee_tokens_per_vbyte?: number
/** Send All Funds boolean */
      is_send_all?: boolean
/** Authenticated LND */
      lnd: LND
/** Log Function */
      log?: Function
/** Confirmations To Wait number */
      target_confirmations?: number
/** Tokens To Send number */
      tokens: number
/** Minimum Confirmations for UTXO Selection number */
      utxo_confirmations?: number
/** Web Socket Server Object */
      wss]: [Object
    }

    @returns via cbk or Promise
    {
/** Total Confirmations number */
      confirmation_count: number
/** Transaction Id Hex string */
      id: string
/** Transaction Is Confirmed boolean */
      is_confirmed: boolean
/** Transaction Is Outgoing boolean */
      is_outgoing: boolean
/** Transaction Tokens number */
      tokens: number
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
/** Transaction Label string */
      description?: string
/** Chain Fee Tokens Per Virtual Byte number */
      fee_tokens_per_vbyte?: number
/** Authenticated LND */
      lnd: LND
/** Log Function */
      log?: Function
      send_to: [{
/** Address string */
        address: string
/** Tokens number */
        tokens: number
      }]
/** Confirmations To Wait number */
      target_confirmations?: number
/** Minimum Confirmations for UTXO Selection number */
      utxo_confirmations?: number
/** Web Socket Server Object */
      wss]: [Object
    }

    @returns via cbk or Promise
    {
/** Total Confirmations number */
      confirmation_count: number
/** Transaction Id Hex string */
      id: string
/** Transaction Is Confirmed boolean */
      is_confirmed: boolean
/** Transaction Is Outgoing boolean */
      is_outgoing: boolean
/** Transaction Tokens number */
      tokens: number
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
/** Node Public Key Hex string */
        public_key: string
/** Score number */
        score: number
      }]
/** Enable Autopilot boolean */
      is_enabled?: boolean
/** Authenticated LND */
      lnd: LND
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
/** Authenticated LND */
      lnd: LND
/** Payment Preimage Hex string */
      secret: string
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
/** Key Family number */
      key_family: number
/** Key Index number */
      key_index: number
/** Authenticated LND */
      lnd: LND
/** Bytes To Hash and Sign Hex Encoded string */
      preimage: string
    }

    @returns via cbk or Promise
    {
/** Signature Hex string */
      signature: string
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
/** Authenticated LND */
      lnd: LND
/** Message string */
      message: string
    }

    @returns via cbk or Promise
    {
/** Signature string */
      signature: string
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
/** Authenticated LND */
      lnd: LND
/** Funded PSBT Hex string */
      psbt: string
    }

    @returns via cbk or Promise
    {
/** Finalized PSBT Hex string */
      psbt: string
/** Signed Raw Transaction Hex string */
      transaction: string
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
/** Key Family number */
        key_family: number
/** Key Index number */
        key_index: number
/** Output Script Hex string */
        output_script: string
/** Output Tokens number */
        output_tokens: number
/** Sighash Type number */
        sighash: number
/** Input Index To Sign number */
        vin: number
/** Witness Script Hex string */
        witness_script: string
      }]
/** Authenticated LND */
      lnd: LND
/** Unsigned Transaction Hex string */
      transaction: string
    }

    @returns via cbk or Promise
    {
/** Signature Hex string */
      signatures: string
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
/** Authenticated LND */
      lnd: LND
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'backup'
    {
/** Backup Hex string */
      backup: string
      channels: [{
/** Backup Hex string */
        backup: string
/** Funding Transaction Id Hex string */
        transaction_id: string
/** Funding Transaction Output Index number */
        transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'block'
    {
/** Block Height number */
      height: number
/** Block Hash string */
      id: string
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
/** Address string */
      bech32_address?: string
/** Chain RPC LND */
      lnd: LND
/** Minimum Confirmations number */
      min_confirmations?: number
/** Minimum Transaction Inclusion Blockchain Height number */
      min_height: number
/** Output Script Hex string */
      output_script?: string
/** Address string */
      p2pkh_address?: string
/** Address string */
      p2sh_address?: string
/** Blockchain Transaction Id string */
      transaction_id?: string
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'confirmation'
    {
/** Block Hash Hex string */
      block: string
/** Block Best Chain Height number */
      height: number
/** Raw Transaction Hex string */
      transaction: string
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
/** Bech32 P2WPKH or P2WSH Address string */
      bech32_address?: string
/** Authenticated LND */
      lnd: LND
/** Minimum Transaction Inclusion Blockchain Height number */
      min_height: number
/** Output Script AKA ScriptPub Hex string */
      output_script?: string
/** Pay to Public Key Hash Address string */
      p2pkh_address?: string
/** Pay to Script Hash Address string */
      p2sh_address?: string
/** Blockchain Transaction Id Hex string */
      transaction_id?: string
/** Blockchain Transaction Output Index number */
      transaction_vout?: number
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'confirmation'
    {
/** Confirmation Block Height number */
      height: number
/** Raw Transaction Hex string */
      transaction: string
/** Spend Outpoint Index number */
      vin: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'channel_active_changed'
    {
/** Channel Is Active boolean */
      is_active: boolean
/** Channel Funding Transaction Id string */
      transaction_id: string
/** Channel Funding Transaction Output Index number */
      transaction_vout: number
    }

    @event 'channel_closed'
    {
/** Closed Channel Capacity Tokens number */
      capacity: number
/** Channel Balance Output Spent By Tx Id string */
      close_balance_spent_by?: string
/** Channel Balance Close Tx Output Index number */
      close_balance_vout?: number
/** Channel Close Confirmation Height number */
      close_confirm_height?: number
      close_payments: [{
/** Payment Is Outgoing boolean */
        is_outgoing: boolean
/** Payment Is Claimed With Preimage boolean */
        is_paid: boolean
/** Payment Resolution Is Pending boolean */
        is_pending: boolean
/** Payment Timed Out And Went Back To Payer boolean */
        is_refunded: boolean
/** Close Transaction Spent By Transaction Id Hex string */
        spent_by?: string
/** Associated Tokens number */
        tokens: number
/** Transaction Id Hex string */
        transaction_id: string
/** Transaction Output Index number */
        transaction_vout: number
      }]
/** Closing Transaction Id Hex string */
      close_transaction_id?: string
/** Channel Close Final Local Balance Tokens number */
      final_local_balance: number
/** Closed Channel Timelocked Tokens number */
      final_time_locked_balance: number
/** Closed Standard Format Channel Id string */
      id?: string
/** Is Breach Close boolean */
      is_breach_close: boolean
/** Is Cooperative Close boolean */
      is_cooperative_close: boolean
/** Is Funding Cancelled Close boolean */
      is_funding_cancel: boolean
/** Is Local Force Close boolean */
      is_local_force_close: boolean
/** Channel Was Closed By Channel Peer boolean */
      is_partner_closed?: boolean
/** Channel Was Initiated By Channel Peer boolean */
      is_partner_initiated?: boolean
/** Is Remote Force Close boolean */
      is_remote_force_close: boolean
/** Partner Public Key Hex string */
      partner_public_key: string
/** Channel Funding Transaction Id Hex string */
      transaction_id: string
/** Channel Funding Output Index number */
      transaction_vout: number
    }

    @event 'channel_opened'
    {
/** Channel Token Capacity number */
      capacity: number
/** Commit Transaction Fee number */
      commit_transaction_fee: number
/** Commit Transaction Weight number */
      commit_transaction_weight: number
/** Coop Close Restricted to Address string */
      cooperative_close_address?: string
/** Prevent Coop Close Until Height number */
      cooperative_close_delay_height?: number
/** Standard Format Channel Id string */
      id: string
/** Channel Active boolean */
      is_active: boolean
/** Channel Is Closing boolean */
      is_closing: boolean
/** Channel Is Opening boolean */
      is_opening: boolean
/** Channel Partner Opened Channel boolean */
      is_partner_initiated: boolean
/** Channel Is Private boolean */
      is_private: boolean
/** Remote Key Is Static boolean */
      is_static_remote_key: boolean
/** Local Balance Tokens number */
      local_balance: number
/** Local Initially Pushed Tokens number */
      local_given?: number
/** Local Reserved Tokens number */
      local_reserve: number
/** Channel Partner Public Key string */
      partner_public_key: string
      pending_payments: [{
/** Payment Preimage Hash Hex string */
        id: string
/** Payment Is Outgoing boolean */
        is_outgoing: boolean
/** Chain Height Expiration number */
        timeout: number
/** Payment Tokens number */
        tokens: number
      }]
/** Received Tokens number */
      received: number
/** Remote Balance Tokens number */
      remote_balance: number
/** Remote Initially Pushed Tokens number */
      remote_given?: number
/** Remote Reserved Tokens number */
      remote_reserve: number
/** Sent Tokens number */
      sent: number
/** Blockchain Transaction Id string */
      transaction_id: string
/** Blockchain Transaction Vout number */
      transaction_vout: number
/** Unsettled Balance Tokens number */
      unsettled_balance: number
    }

    @event 'channel_opening'
    {
/** Blockchain Transaction Id Hex string */
      transaction_id: string
/** Blockchain Transaction Output Index number */
      transaction_vout: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'forward_request`
    {
      accept: () => {}
/** Difference Between Out and In CLTV Height number */
      cltv_delta: number
/** Routing Fee Tokens Rounded Down number */
      fee: number
/** Routing Fee Millitokens string */
      fee_mtokens: string
/** Payment Hash Hex string */
      hash: string
/** Inbound Standard Format Channel Id string */
      in_channel: string
/** Inbound Channel Payment Id number */
      in_payment: number
      messages: [{
/** Message Type number string */
        type: string
/** Raw Value Hex string */
        value: string
      }]
/** Millitokens to Forward To Next Peer string */
      mtokens: string
      onion?: <Hex Serialized Next-Hop Onion Packet To Forward string>
/** Requested Outbound Channel Standard Format Id string */
      out_channel: string
/** Reject Forward Function */
      reject: Function
/** Short Circuit Function */
      settle: Function
/** CLTV Timeout Height number */
      timeout: number
/** Tokens to Forward to Next Peer Rounded Down number */
      tokens: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter Object */
    Object

    @event 'error'
/** Error Object */
    Object

    @event 'forward'
    {
/** Forward Update At ISO 8601 Date string */
      at: string
/** Public Failure Reason string */
      external_failure?: string
/** Inbound Standard Format Channel Id string */
      in_channel?: string
/** Inbound Channel Payment Id number */
      in_payment?: number
/** Private Failure Reason string */
      internal_failure?: string
/** Forward Is Confirmed boolean */
      is_confirmed: boolean
/** Forward Is Failed boolean */
      is_failed: boolean
/** Is Receive boolean */
      is_receive: boolean
/** Is Send boolean */
      is_send: boolean
/** Sending Millitokens number */
      mtokens?: number
/** Outgoing Standard Format Channel Id string */
      out_channel?: string
/** Outgoing Channel Payment Id number */
      out_payment?: number
/** Forward Timeout at Height number */
      timeout?: number
/** Sending Tokens number */
      tokens?: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'channel_updated'
    {
/** Channel Base Fee Millitokens string */
      base_fee_mtokens: string
/** Channel Capacity Tokens number */
      capacity: number
/** Channel CLTV Delta number */
      cltv_delta: number
/** Channel Fee Rate In Millitokens Per Million number */
      fee_rate: number
/** Standard Format Channel Id string */
      id: string
/** Channel Is Disabled boolean */
      is_disabled: boolean
/** Channel Maximum HTLC Millitokens string */
      max_htlc_mtokens?: string
/** Channel Minimum HTLC Millitokens string */
      min_htlc_mtokens: string
/** Target Public Key string */
      public_keys: <Announcing Public Key>, string
/** Channel Transaction Id string */
      transaction_id: string
/** Channel Transaction Output Index number */
      transaction_vout: number
/** Update Received At ISO 8601 Date string */
      updated_at: string
    }

    @event 'channel_closed'
    {
/** Channel Capacity Tokens number */
      capacity?: number
/** Channel Close Confirmed Block Height number */
      close_height: number
/** Standard Format Channel Id string */
      id: string
/** Channel Transaction Id string */
      transaction_id?: string
/** Channel Transaction Output Index number */
      transaction_vout?: number
/** Update Received At ISO 8601 Date string */
      updated_at: string
    }

    @event 'error'
/** Subscription Error */
    Error

    @event 'node_updated'
    {
/** Node Alias string */
      alias: string
/** Node Color string */
      color: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Node Public Key string */
      public_key: string
/** Network Host And Port string */
      sockets]: [string
/** Update Received At ISO 8601 Date string */
      updated_at: string
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
/** Invoice Payment Hash Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event `invoice_updated`
    {
/** Fallback Chain Address string */
      chain_address: string
/** Settled at ISO 8601 Date string */
      confirmed_at?: string
/** ISO 8601 Date string */
      created_at: string
/** Description string */
      description: string
/** Description Hash Hex string */
      description_hash: string
/** ISO 8601 Date string */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit number */
        bit: number
/** Feature is Known boolean */
        is_known: boolean
/** Feature Support is Required To Pay boolean */
        is_required: boolean
/** Feature Type string */
        type: string
      }]
/** Payment Hash string */
      id: string
/** Invoice is Canceled boolean */
      is_canceled?: boolean
/** Invoice is Confirmed boolean */
      is_confirmed: boolean
/** HTLC is Held boolean */
      is_held?: boolean
/** Invoice is Outgoing boolean */
      is_outgoing: boolean
/** Invoice is Private boolean */
      is_private: boolean
/** Invoiced Millitokens string */
      mtokens: string
      payments: [{
/** Payment Settled At ISO 8601 Date string */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date string */
        created_at: string
/** Payment Held Since Block Height number */
        created_height: number
/** Incoming Payment Through Channel Id string */
        in_channel: string
/** Payment is Canceled boolean */
        is_canceled: boolean
/** Payment is Confirmed boolean */
        is_confirmed: boolean
/** Payment is Held boolean */
        is_held: boolean
        messages: [{
/** Message Type number string */
          type: string
/** Raw Value Hex string */
          value: string
        }]
/** Incoming Payment Millitokens string */
        mtokens: string
/** Pending Payment Channel HTLC Index number */
        pending_index?: number
/** Payment Tokens number */
        tokens: number
      }]
/** Received Tokens number */
      received: number
/** Received Millitokens string */
      received_mtokens: string
/** Bolt 11 Invoice string */
      request: string
      routes: [[{
/** Base Routing Fee In Millitokens number */
        base_fee_mtokens: number
/** Standard Format Channel Id string */
        channel: string
/** CLTV Blocks Delta number */
        cltv_delta: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate: number
/** Public Key Hex string */
        public_key: string
      }]]
/** Secret Preimage Hex string */
      secret: string
/** Tokens number */
      tokens: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'invoice_updated'
    {
/** Fallback Chain Address string */
      chain_address?: string
/** Final CLTV Delta number */
      cltv_delta: number
/** Confirmed At ISO 8601 Date string */
      confirmed_at?: string
/** Created At ISO 8601 Date string */
      created_at: string
/** Description string */
      description: string
/** Description Hash Hex string */
      description_hash: string
/** Expires At ISO 8601 Date string */
      expires_at: string
      features: [{
/** Feature Bit number */
        bit: number
/** Is Known Feature boolean */
        is_known: boolean
/** Feature Is Required boolean */
        is_required: boolean
/** Feature Name string */
        name: string
      }]
/** Invoice Payment Hash Hex string */
      id: string
/** Invoice is Confirmed boolean */
      is_confirmed: boolean
/** Invoice is Outgoing boolean */
      is_outgoing: boolean
/** Invoice is Push Payment boolean */
      is_push?: boolean
      payments: [{
/** Payment Settled At ISO 8601 Date string */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date string */
        created_at: string
/** Payment Held Since Block Height number */
        created_height: number
/** Incoming Payment Through Channel Id string */
        in_channel: string
/** Payment is Canceled boolean */
        is_canceled: boolean
/** Payment is Confirmed boolean */
        is_confirmed: boolean
/** Payment is Held boolean */
        is_held: boolean
        messages: [{
/** Message Type number string */
          type: string
/** Raw Value Hex string */
          value: string
        }]
/** Incoming Payment Millitokens string */
        mtokens: string
/** Pending Payment Channel HTLC Index number */
        pending_index?: number
/** Payment Tokens number */
        tokens: number
/** Total Payment Millitokens string */
        total_mtokens?: string
      }]
/** Received Tokens number */
      received: number
/** Received Millitokens string */
      received_mtokens: string
/** BOLT 11 Payment Request string */
      request?: string
/** Payment Secret Hex string */
      secret: string
/** Invoiced Tokens number */
      tokens: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'channel_request'
    {
/** Accept Request Function */
      accept: Function
/** Restrict Coop Close To Address string */
        cooperative_close_address?: string
/** Required Confirmations Before Channel Open number */
        min_confirmations?: number
/** Peer Unilateral Balance Output CSV Delay number */
        remote_csv?: number
/** Minimum Tokens Peer Must Keep On Their Side number */
        remote_reserve?: number
/** Maximum Slots For Attaching HTLCs number */
        remote_max_htlcs?: number
/** Maximum HTLCs Value Millitokens string */
        remote_max_pending_mtokens?: string
/** Minimium HTLC Value Millitokens string */
        remote_min_htlc_mtokens?: string
      }) -> {}
/** Capacity Tokens number */
      capacity: number
/** Chain Id Hex string */
      chain: string
/** Commitment Transaction Fee number */
      commit_fee_tokens_per_vbyte: number
/** CSV Delay Blocks number */
      csv_delay: number
/** Request Id Hex string */
      id: string
/** Channel Local Tokens Balance number */
      local_balance: number
/** Channel Local Reserve Tokens number */
      local_reserve: number
/** Maximum Millitokens Pending In Channel string */
      max_pending_mtokens: string
/** Maximum Pending Payments number */
      max_pending_payments: number
/** Minimum Chain Output Tokens number */
      min_chain_output: number
/** Minimum HTLC Millitokens string */
      min_htlc_mtokens: string
/** Peer Public Key Hex string */
      partner_public_key: string
/** Reject Request Function */
      reject: Function
/** 500 Character Limited Rejection Reason string */
        reason?: string
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
/** Payment Request Hash Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter Object */
    Object

    @event 'confirmed'
    {
/** Total Fee Millitokens To Pay string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Channel Capacity Tokens number */
        channel_capacity: number
/** Routing Fee Tokens number */
        fee: number
/** Fee Millitokens string */
        fee_mtokens: string
/** Forwarded Tokens number */
        forward: number
/** Forward Millitokens string */
        forward_mtokens: string
/** Public Key Hex string */
        public_key: string
/** Timeout Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Total Millitokens Paid string */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Preimage Hex string */
      secret: string
/** Expiration Block Height number */
      timeout: number
/** Tokens Paid number */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance boolean */
      is_insufficient_balance: boolean
/** Failed Due to Payment Rejected At Destination boolean */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout boolean */
      is_pathfinding_timeout: boolean
/** Failed Due to Absence of Path Through Graph boolean */
      is_route_not_found: boolean
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Destination Public Key string */
      destination: string
      features?: [{
/** Feature Bit number */
        bit: number
      }]
/** Payment Request Hash Hex string */
      id?: string
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths number */
      max_paths?: number
/** Maximum Height of Payment Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Pay Out of Outgoing Channel Id string */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids string */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
      routes?: [[{
/** Base Routing Fee In Millitokens string */
        base_fee_mtokens?: string
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Tokens to Pay number */
      tokens?: number
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter Object */
    Object

    @event 'confirmed'
    {
/** Fee Tokens Paid number */
      fee: number
/** Total Fee Millitokens Paid string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Channel Capacity Tokens number */
        channel_capacity: number
/** Fee Millitokens string */
        fee_mtokens: string
/** Forward Millitokens string */
        forward_mtokens: string
/** Public Key Hex string */
        public_key: string
/** Timeout Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id?: string
/** Total Millitokens To Pay string */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Preimage Hex string */
      secret: string
/** Total Tokens Paid Rounded Down number */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance boolean */
      is_insufficient_balance: boolean
/** Failed Due to Invalid Payment boolean */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout boolean */
      is_pathfinding_timeout: boolean
/** Failed Due to Route Not Found boolean */
      is_route_not_found: boolean
      route?: {
/** Route Total Fee Tokens Rounded Down number */
        fee: number
/** Route Total Fee Millitokens string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Hop Forwarding Fee Rounded Down Tokens number */
          fee: number
/** Hop Forwarding Fee Millitokens string */
          fee_mtokens: string
/** Hop Forwarding Tokens Rounded Down number */
          forward: number
/** Hop Forwarding Millitokens string */
          forward_mtokens: string
/** Hop Sending To Public Key Hex string */
          public_key: string
/** Hop CTLV Expiration Height number */
          timeout: number
        }]
/** Payment Sending Millitokens string */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Sending Tokens Rounded Up number */
        safe_tokens: number
/** Payment CLTV Expiration Height number */
        timeout: number
/** Payment Sending Tokens Rounded Down number */
        tokens: number
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
/** Pay Through Specific Final Hop Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens To Pay number */
      max_fee?: number
/** Maximum Fee Millitokens to Pay string */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths number */
      max_paths?: number
/** Maximum Height of Payment Timeout number */
      max_timeout_height?: number
      messages?: [{
/** Message Type number string */
        type: string
/** Message Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Pay string */
      mtokens?: string
/** Pay Out of Outgoing Channel Id string */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids string */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request string */
      request: string
/** Tokens To Pay number */
      tokens?: number
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter Object */
    Object

    @event 'confirmed'
    {
/** Fee Tokens number */
      fee: number
/** Total Fee Millitokens To Pay string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Channel Capacity Tokens number */
        channel_capacity: number
/** Fee Millitokens string */
        fee_mtokens: string
/** Forward Millitokens string */
        forward_mtokens: string
/** Public Key Hex string */
        public_key: string
/** Timeout Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Total Millitokens Paid string */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Preimage Hex string */
      secret: string
/** Expiration Block Height number */
      timeout: number
/** Total Tokens Paid number */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance boolean */
      is_insufficient_balance: boolean
/** Failed Due to Invalid Payment boolean */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout boolean */
      is_pathfinding_timeout: boolean
/** Failed Due to Route Not Found boolean */
      is_route_not_found: boolean
      route?: {
/** Route Total Fee Tokens Rounded Down number */
        fee: number
/** Route Total Fee Millitokens string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Hop Forwarding Fee Rounded Down Tokens number */
          fee: number
/** Hop Forwarding Fee Millitokens string */
          fee_mtokens: string
/** Hop Forwarding Tokens Rounded Down number */
          forward: number
/** Hop Forwarding Millitokens string */
          forward_mtokens: string
/** Hop Sending To Public Key Hex string */
          public_key: string
/** Hop CTLV Expiration Height number */
          timeout: number
        }]
/** Payment Sending Millitokens string */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Sending Tokens Rounded Up number */
        safe_tokens: number
/** Payment CLTV Expiration Height number */
        timeout: number
/** Payment Sending Tokens Rounded Down number */
        tokens: number
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
/** Payment Hash Hex string */
      id?: string
/** Authenticated LND */
      lnd: LND
/** Time to Spend Finding a Route Milliseconds number */
      pathfinding_timeout?: number
      routes: [{
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
      }]
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'failure'
    {
      failure: [
/** Code number */
        number
/** Failure Message string */
        string
        {
/** Standard Format Channel Id string */
          channel: string
/** Millitokens string */
          mtokens?: string
          policy?: {
/** Base Fee Millitokens string */
            base_fee_mtokens: string
/** Locktime Delta number */
            cltv_delta: number
/** Fees Charged in Millitokens Per Million number */
            fee_rate: number
/** Channel is Disabled boolean */
            is_disabled?: boolean
/** Maximum HLTC Millitokens value string */
            max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value string */
            min_htlc_mtokens: string
          }
/** Public Key Hex string */
          public_key: string
          update?: {
/** Chain Id Hex string */
            chain: string
/** Channel Flags number */
            channel_flags: number
/** Extra Opaque Data Hex string */
            extra_opaque_data: string
/** Message Flags number */
            message_flags: number
/** Channel Update Signature Hex string */
            signature: string
          }
        }
      ]
    }

    @event 'paying'
    {
      route: {
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
      }
    }

    @event 'routing_failure'
    {
/** Standard Format Channel Id string */
      channel?: string
/** Failure Hop Index number */
      index?: number
/** Failure Related Millitokens string */
      mtokens?: string
      policy?: {
/** Base Fee Millitokens string */
        base_fee_mtokens: string
/** Locktime Delta number */
        cltv_delta: number
/** Fees Charged in Millitokens Per Million number */
        fee_rate: number
/** Channel is Disabled boolean */
        is_disabled?: boolean
/** Maximum HLTC Millitokens value string */
        max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value string */
        min_htlc_mtokens: string
      }
/** Public Key Hex string */
      public_key: string
/** Failure Reason string */
      reason: string
      route: {
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
      }
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Failure Related CLTV Timeout Height number */
      timeout_height?: number
      update?: {
/** Chain Id Hex string */
        chain: string
/** Channel Flags number */
        channel_flags: number
/** Extra Opaque Data Hex string */
        extra_opaque_data: string
/** Message Flags number */
        message_flags: number
/** Channel Update Signature Hex string */
        signature: string
      }
    }

    @event 'success'
    {
/** Fee Paid Tokens number */
      fee: number
/** Fee Paid Millitokens string */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id string */
        channel: string
/** Hop Channel Capacity Tokens number */
        channel_capacity: number
/** Hop Forward Fee Millitokens string */
        fee_mtokens: string
/** Hop Forwarded Millitokens string */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height number */
        timeout: number
      }]
/** Payment Hash Hex string */
      id: string
/** Is Confirmed boolean */
      is_confirmed: boolean
/** Is Outoing boolean */
      is_outgoing: boolean
/** Total Millitokens Sent string */
      mtokens: string
      route: {
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
      }
/** Payment Forwarding Fee Rounded Up Tokens number */
      safe_fee: number
/** Payment Tokens Rounded Up number */
      safe_tokens: number
/** Payment Secret Preimage Hex string */
      secret: string
/** Total Tokens Sent number */
      tokens: number
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'connected'
    {
/** Connected Peer Public Key Hex string */
      public_key: string
    }

    @event 'disconnected'
    {
/** Disconnected Peer Public Key Hex string */
      public_key: string
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
/** Final CLTV Delta number */
      cltv_delta?: number
/** Destination Public Key Hex string */
      destination: string
      features?: [{
/** Feature Bit number */
        bit: number
      }]
      ignore?: [{
/** Public Key Hex string */
        from_public_key: string
/** To Public Key Hex string */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex string */
      incoming_peer?: string
/** Authenticated LND */
      lnd: LND
/** Maximum Fee Tokens number */
      max_fee?: number
/** Maximum Fee Millitokens to Probe string */
      max_fee_mtokens?: string
/** Maximum CLTV Timeout Height number */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number string */
        type: string
/** Message To Final Destination Raw Value Hex Encoded string */
        value: string
      }]
/** Millitokens to Probe string */
      mtokens?: string
/** Outgoing Channel Id string */
      outgoing_channel?: string
/** Skip Individual Path Attempt After Milliseconds number */
      path_timeout_ms?: number
/** Payment Identifier Hex string */
      payment?: string
/** Fail Entire Probe After Milliseconds number */
      probe_timeout_ms?: number
      routes?: [[{
/** Base Routing Fee In Millitokens number */
        base_fee_mtokens?: number
/** Channel Capacity Tokens number */
        channel_capacity?: number
/** Standard Format Channel Id string */
        channel?: string
/** CLTV Blocks Delta number */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
        fee_rate?: number
/** Forward Edge Public Key Hex string */
        public_key: string
      }]]
/** Tokens to Probe number */
      tokens?: number
/** Total Millitokens Across Paths string */
      total_mtokens?: string
    }

    @returns
/** Probe Subscription Event Emitter Object */
    Object

    @event 'error'
/** Failure Message string */
    <Failure Code number>, string

    @event 'probe_success'
    {
      route: {
/** Route Confidence Score Out Of One Million number */
        confidence?: number
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Payment Identifier Hex string */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Sent Tokens Rounded Up number */
        safe_tokens: number
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
/** Total Millitokens string */
        total_mtokens?: string
      }
    }

    @event 'probing'
    {
      route: {
/** Route Confidence Score Out Of One Million number */
        confidence?: number
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Payment Identifier Hex string */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Sent Tokens Rounded Up number */
        safe_tokens: number
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
/** Total Millitokens string */
        total_mtokens?: string
      }
    }

    @event 'routing_failure'
    {
/** Standard Format Channel Id string */
      channel?: string
/** Millitokens string */
      mtokens?: string
      policy?: {
/** Base Fee Millitokens string */
        base_fee_mtokens: string
/** Locktime Delta number */
        cltv_delta: number
/** Fees Charged in Millitokens Per Million number */
        fee_rate: number
/** Channel is Disabled boolean */
        is_disabled?: boolean
/** Maximum HLTC Millitokens Value string */
        max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value string */
        min_htlc_mtokens: string
      }
/** Public Key Hex string */
      public_key: string
/** Failure Reason string */
      reason: string
      route: {
/** Route Confidence Score Out Of One Million number */
        confidence?: number
/** Total Fee Tokens To Pay number */
        fee: number
/** Total Fee Millitokens To Pay string */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id string */
          channel: string
/** Channel Capacity Tokens number */
          channel_capacity: number
/** Fee number */
          fee: number
/** Fee Millitokens string */
          fee_mtokens: string
/** Forward Tokens number */
          forward: number
/** Forward Millitokens string */
          forward_mtokens: string
/** Public Key Hex string */
          public_key: string
/** Timeout Block Height number */
          timeout: number
        }]
        messages?: [{
/** Message Type number string */
          type: string
/** Message Raw Value Hex Encoded string */
          value: string
        }]
/** Total Millitokens To Pay string */
        mtokens: string
/** Payment Identifier Hex string */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens number */
        safe_fee: number
/** Payment Sent Tokens Rounded Up number */
        safe_tokens: number
/** Expiration Block Height number */
        timeout: number
/** Total Tokens To Pay number */
        tokens: number
/** Total Millitokens string */
        total_mtokens?: string
      }
      update?: {
/** Chain Id Hex string */
        chain: string
/** Channel Flags number */
        channel_flags: number
/** Extra Opaque Data Hex string */
        extra_opaque_data: string
/** Message Flags number */
        message_flags: number
/** Channel Update Signature Hex string */
        signature: string
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
/** Authenticated LND */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter Object */
    Object

    @event 'chain_transaction'
    {
/** Block Hash string */
      block_id?: string
/** Confirmation Count number */
      confirmation_count?: number
/** Confirmation Block Height number */
      confirmation_height?: number
/** Created ISO 8601 Date string */
      created_at: string
/** Fees Paid Tokens number */
      fee?: number
/** Transaction Id string */
      id: string
/** Is Confirmed boolean */
      is_confirmed: boolean
/** Transaction Outbound boolean */
      is_outgoing: boolean
/** Address string */
      output_addresses: string
/** Tokens Including Fee number */
      tokens: number
/** Raw Transaction Hex string */
      transaction?: string
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
/** Base64 or Hex Serialized LND TLS Cert */
      cert?: Cert
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
/** Unlocker LND GRPC Api Object */
        unlocker: Object
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
/** Lock Id Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
/** Unspent Transaction Id Hex string */
      transaction_id: string
/** Unspent Transaction Output Index number */
      transaction_vout: number
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
/** Unauthenticated LND */
      lnd: LND
/** Wallet Password string */
      password: string
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
/** Transaction Label string */
      description: string
/** Transaction Id Hex string */
      id: string
/** Authenticated LND */
      lnd: LND
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
/** Add Socket string */
      add_socket?: string
/** Authenticated LND */
      lnd: LND
/** Watchtower Public Key Hex string */
      public_key: string
/** Remove Socket string */
      remove_socket?: string
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
/** Base Fee Millitokens Charged number */
      base_fee_mtokens?: number
/** Base Fee Tokens Charged number */
      base_fee_tokens?: number
/** HTLC CLTV Delta number */
      cltv_delta?: number
/** Fee Rate In Millitokens Per Million number */
      fee_rate?: number
/** Authenticated LND */
      lnd: LND
/** Maximum HTLC Millitokens to Forward string */
      max_htlc_mtokens?: string
/** Minimum HTLC Millitokens to Forward string */
      min_htlc_mtokens?: string
/** Channel Funding Transaction Id string */
      transaction_id?: string
/** Channel Funding Transaction Output Index number */
      transaction_vout?: number
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
/** Individual Channel Backup Hex string */
      backup: string
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** LND Error Object */
      err?: Object
/** Backup is Valid boolean */
      is_valid: boolean
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
/** Funding Transaction Id Hex string */
        transaction_id: string
/** Funding Transaction Output Index number */
        transaction_vout: number
      }]
/** Authenticated LND */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Backup is Valid boolean */
      is_valid: boolean
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
/** Authenticated LND */
      lnd: LND
/** Message Preimage Bytes Hex Encoded string */
      preimage: string
/** Signature Valid For Public Key Hex string */
      public_key: string
/** Signature Hex string */
      signature: string
    }

    @returns via cbk or Promise
    {
/** Signature is Valid boolean */
      is_valid: boolean
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
/** Authenticated LND */
      lnd: LND
/** Message string */
      message: string
/** Signature Hex string */
      signature: string
    }

    @returns via cbk or Promise
    {
/** Public Key Hex string */
      signed_by: string
    }

Example:

```node
const {verifyMessage} = require('ln-service');
const message = 'foo';
const signature = 'badSignature';
const signedBy = (await verifyMessage({lnd, message, signature})).signed_by;
```

