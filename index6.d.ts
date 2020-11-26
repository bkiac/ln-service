

### addPeer

Add a peer if possible (not self, or already connected)

Requires `peers:write` permission

`timeout` is not supported in LND 0.11.1 and below

    {
/** Add Peer as Temporary Peer */
      is_temporary?: boolean
/** Authenticated */
      lnd: LND
/** Public Key */
      public_key: string
/** Retry */
      retry_count?: number
/** Delay Retry By */
      retry_delay?: number
/** Host Network Address And Optional */
      socket: string
/** Connection Attempt Timeout Milliseconds */
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
/** Base64 or Hex Serialized LND TLS */
      cert?: Cert
/** Base64 or Hex Serialized Macaroon */
      macaroon: string
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
/** Autopilot API Methods */
        autopilot: Object
/** ChainNotifier API Methods */
        chain: Object
/** Default API Methods */
        default: Object
/** Invoices API Methods */
        invoices: Object
/** Router API Methods */
        router: Object
/** Signer Methods API */
        signer: Object
/** Watchtower Client Methods */
        tower_client: Object
/** Watchtower Server Methods API */
        tower_server: Object
/** WalletKit gRPC Methods API */
        wallet: Object
/** Version Methods API */
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
/** Transaction Label */
      description?: string
/** Authenticated */
      lnd: LND
/** Transaction Hex */
      transaction: string
    }

    @returns via cbk or Promise
    {
/** Transaction Id Hex */
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
/** Capacity Tokens */
        capacity: number
/** Standard Channel Id */
        id: string
        policies: [{
/** Base Fee Millitokens */
          base_fee_mtokens: string
/** CLTV Delta */
          cltv_delta: number
/** Fee Rate */
          fee_rate: number
/** Channel is Disabled */
          is_disabled: boolean
/** Maximum HTLC Millitokens */
          max_htlc_mtokens: string
/** Minimum HTLC Millitokens */
          min_htlc_mtokens: string
/** Public Key Hex */
          public_key: string
        }]
      }]
/** End Public Key Hex */
      end: string
      ignore?: [{
/** Standard Format Channel Id */
        channel?: string
/** Public Key Hex */
        public_key: string
      }]
/** Millitokens */
      mtokens: number
/** Start Public Key Hex */
      start: string
    }

    @throws
    <Error>

    @returns
    {
      hops?: [{
/** Base Fee Millitokens */
        base_fee_mtokens: string
/** Standard Channel Id */
        channel: string
/** Channel Capacity Tokens */
        channel_capacity: number
/** CLTV Delta */
        cltv_delta: number
/** Fee Rate */
        fee_rate: number
/** Public Key Hex */
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
/** Capacity Tokens */
        capacity: number
/** Standard Channel Id */
        id: string
        policies: [{
/** Base Fee Millitokens */
          base_fee_mtokens: string
/** CLTV Delta */
          cltv_delta: number
/** Fee Rate */
          fee_rate: number
/** Channel is Disabled */
          is_disabled: boolean
/** Maximum HTLC Millitokens */
          max_htlc_mtokens: string
/** Minimum HTLC Millitokens */
          min_htlc_mtokens: string
/** Public Key Hex */
          public_key: string
        }]
      }]
/** End Public Key Hex */
      end: string
/** Paths To Return Limit */
      limit?: number
/** Millitokens */
      mtokens: number
/** Start Public Key Hex */
      start: string
    }

    @throws
    <Error>

    @returns
    {
      paths?: [{
        hops: [{
/** Base Fee Millitokens */
          base_fee_mtokens: string
/** Standard Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** CLTV Delta */
          cltv_delta: number
/** Fee Rate */
          fee_rate: number
/** Public Key Hex */
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
/** Payment Preimage Hash Hex */
      id: string
/** Authenticated RPC */
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
/** Pending Channel Id Hex */
      id: string
/** Authenticated */
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
/** Current Password */
      current_password: string
/** Unauthenticated */
      lnd: LND
/** New Password */
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
/** Request Sending Local Channel Funds To Address */
      address?: string
/** Standard Format Channel Id */
      id?: string
/** Is Force Close */
      is_force_close?: boolean
/** Authenticated */
      lnd: LND
/** Peer Public Key */
      public_key?: string
/** Peer Socket */
      socket?: string
/** Confirmation Target */
      target_confirmations?: number
/** Tokens Per Virtual Byte */
      tokens_per_vbyte?: number
/** Transaction Id Hex */
      transaction_id?: string
/** Transaction Output Index */
      transaction_vout?: number
    }

    @returns via cbk or Promise
    {
/** Closing Transaction Id Hex */
      transaction_id: string
/** Closing Transaction Vout */
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
/** Authenticated */
      lnd: LND
/** Watchtower Public Key Hex */
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
/** Receive Address Type */
      format: string
      is_unused?: <Get As-Yet Unused Address boolean>
/** Authenticated */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Invoice Description */
      description?: string
/** Hashed Description of Payment Hex */
      description_hash?: string
/** Expires At ISO 8601 Date */
      expires_at?: string
/** Payment Hash Hex */
      id?: string
/** Is Fallback Address Included */
      is_fallback_included?: boolean
/** Is Fallback Address Nested */
      is_fallback_nested?: boolean
/** Invoice Includes Private Channels */
      is_including_private_channels?: boolean
/** Authenticated */
      lnd: LND
/** Millitokens */
      mtokens?: string
/** Tokens */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Backup Address */
      chain_address?: string
/** ISO 8601 Date */
      created_at: string
/** Description */
      description: string
/** Payment Hash Hex */
      id: string
/** Millitokens */
      mtokens: number
/** BOLT 11 Encoded Payment Request */
      request: string
/** Hex Encoded Payment Secret */
      secret?: string
/** Tokens */
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
/** CLTV Delta */
      cltv_delta?: number
/** Invoice Description */
      description?: string
/** Hashed Description of Payment Hex */
      description_hash?: string
/** Expires At ISO 8601 Date */
      expires_at?: string
/** Is Fallback Address Included */
      is_fallback_included?: boolean
/** Is Fallback Address Nested */
      is_fallback_nested?: boolean
/** Invoice Includes Private Channels */
      is_including_private_channels?: boolean
/** Authenticated */
      lnd: LND
/** Payment Preimage Hex */
      secret?: string
/** Millitokens */
      mtokens?: string
/** Tokens */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Backup Address */
      chain_address?: string
/** ISO 8601 Date */
      created_at: string
/** Description */
      description?: string
/** Payment Hash Hex */
      id: string
/** Millitokens */
      mtokens?: string
/** BOLT 11 Encoded Payment Request */
      request: string
/** Hex Encoded Payment Secret */
      secret: string
/** Tokens */
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
/** Unauthenticated */
      lnd: LND
/** Seed Passphrase */
      passphrase?: string
    }

    @returns via cbk or Promise
    {
/** Cipher Seed Mnemonic */
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
/** Destination Public Key Hex */
      destination: string
/** Request Human Readable Part */
      hrp: string
/** Request Hash Signature Hex */
      signature: string
/** Request Tag Word */
      tags: number
    }

    @throws
    <Error>

    @returns
    {
/** BOLT 11 Encoded Payment Request */
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
/** Chain Address */
      chain_addresses]: [string
/** CLTV Delta */
      cltv_delta?: number
/** Invoice Creation Date ISO 8601 */
      created_at?: string
/** Description */
      description?: string
/** Description Hash Hex */
      description_hash?: string
/** Public Key */
      destination: string
/** ISO 8601 Date */
      expires_at?: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
      }]
/** Preimage SHA256 Hash Hex */
      id: string
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
/** Network Name */
      network: string
/** Payment Identifier Hex */
      payment?: string
      routes?: [[{
/** Base Fee Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** Final CLTV Expiration Blocks Delta */
        cltv_delta?: number
/** Fees Charged in Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Requested Chain Tokens */
      tokens?: number
    }

    @returns
    {
/** Payment Request Signature Hash Hex */
      hash: string
/** Human Readable Part of Payment Request */
      hrp: string
/** Signature Hash Preimage Hex */
      preimage: string
/** Data Tag */
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
/** Unauthenticated */
      lnd: LND
/** AEZSeed Encryption Passphrase */
      passphrase?: string
/** Wallet Password */
      password: string
/** Seed Mnemonic */
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
/** Authenticated */
      lnd: LND
/** BOLT 11 Payment Request */
      request: string
    }

    @returns via cbk or Promise
    {
/** Fallback Chain Address */
      chain_address: string
/** Final CLTV Delta */
      cltv_delta?: number
/** Payment Description */
      description: string
/** Payment Longer Description Hash */
      description_hash: string
/** Public Key */
      destination: string
/** ISO 8601 Date */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required To Pay */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Payment Hash */
      id: string
/** Requested Millitokens */
      mtokens: string
/** Payment Identifier Hex Encoded */
      payment?: string
      routes: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Requested Tokens Rounded Up */
      safe_tokens: number
/** Requested Tokens Rounded Down */
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
/** Authenticated */
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
/** Authenticated */
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
/** Key Family */
      key_family?: number
/** Key Index */
      key_index?: number
/** Authenticated */
      lnd: LND
/** Public Key Hex */
      partner_public_key: string
    }

    @returns via cbk or Promise
    {
/** Shared Secret Hex */
      secret: string
    }

### disconnectWatchtower

Disconnect a watchtower

Requires LND built with `wtclientrpc` build tag

Requires `offchain:write` permission

    {
/** Authenticated */
      lnd: LND
/** Watchtower Public Key Hex */
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
/** Pending Channel Id Hex */
      channels: string
/** Signed Funding Transaction PSBT Hex */
      funding: string
/** Authenticated */
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
/** Chain Fee Tokens Per Virtual Byte */
      fee_tokens_per_vbyte?: number
      inputs?: [{
/** Unspent Transaction Id Hex */
        transaction_id: string
/** Unspent Transaction Output Index */
        transaction_vout: number
      }]
/** Authenticated */
      lnd: LND
      outputs?: [{
/** Chain Address */
        address: string
/** Send Tokens Tokens */
        tokens: number
      }]
/** Confirmations To Wait */
      target_confirmations?: number
/** Existing PSBT Hex */
      psbt?: string
    }

    @returns via cbk or Promise
    {
      inputs: [{
/** UTXO Lock Expires At ISO 8601 Date */
        lock_expires_at?: string
/** UTXO Lock Id Hex */
        lock_id?: string
/** Unspent Transaction Id Hex */
        transaction_id: string
/** Unspent Transaction Output Index */
        transaction_vout: number
      }]
      outputs: [{
/** Spends To a Generated Change Output */
        is_change: boolean
/** Output Script Hex */
        output_script: string
/** Send Tokens Tokens */
        tokens: number
      }]
/** Unsigned PSBT Hex */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Root Access Id */
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
/** Authenticated */
      lnd: LND
/** Get Score For Public Key Hex */
      node_scores]: [string
    }

    @returns via cbk or Promise
    {
/** Autopilot is Enabled */
      is_enabled: boolean
      nodes: [{
        local_preferential_score: <Local-adjusted Pref Attachment Score number>
        local_score: <Local-adjusted Externally Set Score number>
/** Preferential Attachment Score */
        preferential_score: number
/** Node Public Key Hex */
        public_key: string
/** Externally Set Score */
        score: number
        weighted_local_score: <Combined Weighted Locally-Adjusted Score number>
/** Combined Weighted Score */
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
/** Authenticated */
      lnd: LND
/** Funding Transaction Id Hex */
      transaction_id: string
/** Funding Transaction Output Index */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Channel Backup Hex */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** All Channels Backup Hex */
      backup: string
      channels: {
/** Individualized Channel Backup Hex */
        backup: string
/** Channel Funding Transaction Id Hex */
        transaction_id: string
/** Channel Funding Transaction Output Index */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Confirmed Chain Balance Tokens */
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
/** Authenticated */
      lnd: LND
      send_to: [{
/** Address */
        address: string
/** Tokens */
        tokens: number
      }]
/** Target Confirmations */
      target_confirmations?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens */
      fee: number
/** Fee Tokens Per VByte */
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
/** Future Blocks Confirmation */
      confirmation_target?: number
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Tokens Per Virtual Byte */
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
/** Confirmed After Current Best Chain Block Height */
      after?: number
/** Confirmed Before Current Best Chain Block Height */
      before?: number
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      transactions: [{
/** Block Hash */
        block_id?: string
/** Confirmation Count */
        confirmation_count?: number
/** Confirmation Block Height */
        confirmation_height?: number
/** Created ISO 8601 Date */
        created_at: string
/** Transaction Label */
        description?: string
/** Fees Paid Tokens */
        fee?: number
/** Transaction Id */
        id: string
/** Is Confirmed */
        is_confirmed: boolean
/** Transaction Outbound */
        is_outgoing: boolean
/** Address */
        output_addresses: string
/** Tokens Including Fee */
        tokens: number
/** Raw Transaction Hex */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Channels Balance Tokens */
      channel_balance: number
/** Channels Balance Millitokens */
      channel_balance_mtokens?: string
/** Inbound Liquidity Tokens */
      inbound?: number
/** Inbound Liquidity Millitokens */
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
/** Standard Format Channel Id */
      id: string
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Maximum Tokens */
      capacity: number
/** Standard Format Channel Id */
      id: string
      policies: [{
/** Base Fee Millitokens */
        base_fee_mtokens?: string
/** Locktime Delta */
        cltv_delta?: number
/** Fees Charged Per Million Millitokens */
        fee_rate?: number
/** Channel Is Disabled */
        is_disabled?: boolean
/** Maximum HTLC Millitokens Value */
        max_htlc_mtokens?: string
/** Minimum HTLC Millitokens Value */
        min_htlc_mtokens?: string
/** Node Public Key */
        public_key: string
/** Policy Last Updated At ISO 8601 Date */
        updated_at?: string
      }]
/** Transaction Id Hex */
      transaction_id: string
/** Transaction Output Index */
      transaction_vout: number
/** Last Update Epoch ISO 8601 Date */
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
/** Limit Results To Only Active Channels */
      is_active?: boolean
/** Limit Results To Only Offline Channels */
      is_offline?: boolean
/** Limit Results To Only Private Channels */
      is_private?: boolean
/** Limit Results To Only Public Channels */
      is_public?: boolean
/** Authenticated */
      lnd: LND
/** Only Channels With Public Key Hex */
      partner_public_key?: string
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Channel Token Capacity */
        capacity: number
/** Commit Transaction Fee */
        commit_transaction_fee: number
/** Commit Transaction Weight */
        commit_transaction_weight: number
/** Coop Close Restricted to Address */
        cooperative_close_address?: string
/** Prevent Coop Close Until Height */
        cooperative_close_delay_height?: number
/** Standard Format Channel Id */
        id: string
/** Channel Active */
        is_active: boolean
/** Channel Is Closing */
        is_closing: boolean
/** Channel Is Opening */
        is_opening: boolean
/** Channel Partner Opened Channel */
        is_partner_initiated: boolean
/** Channel Is Private */
        is_private: boolean
/** Remote Key Is Static */
        is_static_remote_key: boolean
/** Local Balance Tokens */
        local_balance: number
/** Local CSV Blocks Delay */
        local_csv?: number
        local_dust?: <Remote Non-Enforceable Amount Tokens number>
/** Local Initially Pushed Tokens */
        local_given?: number
/** Local Maximum Attached HTLCs */
        local_max_htlcs?: number
/** Local Maximum Pending Millitokens */
        local_max_pending_mtokens?: string
/** Local Minimum HTLC Millitokens */
        local_min_htlc_mtokens?: string
/** Local Reserved Tokens */
        local_reserve: number
/** Channel Partner Public Key */
        partner_public_key: string
        pending_payments: [{
/** Payment Preimage Hash Hex */
          id: string
/** Forward Inbound From Channel Id */
          in_channel?: string
/** Payment Index on Inbound Channel */
          in_payment?: number
/** Payment is a Forward */
          is_forward?: boolean
/** Payment Is Outgoing */
          is_outgoing: boolean
/** Forward Outbound To Channel Id */
          out_channel?: string
/** Payment Index on Outbound Channel */
          out_payment?: number
/** Payment Attempt Id */
          payment?: number
/** Chain Height Expiration */
          timeout: number
/** Payment Tokens */
          tokens: number
        }]
/** Received Tokens */
        received: number
/** Remote Balance Tokens */
        remote_balance: number
/** Remote CSV Blocks Delay */
        remote_csv?: number
        remote_dust?: <Remote Non-Enforceable Amount Tokens number>
/** Remote Initially Pushed Tokens */
        remote_given?: number
/** Remote Maximum Attached HTLCs */
        remote_max_htlcs?: number
/** Remote Maximum Pending Millitokens */
        remote_max_pending_mtokens?: string
/** Remote Minimum HTLC Millitokens */
        remote_min_htlc_mtokens?: string
/** Remote Reserved Tokens */
        remote_reserve: number
/** Sent Tokens */
        sent: number
/** Monitoring Uptime Channel Down Milliseconds */
        time_offline?: number
/** Monitoring Uptime Channel Up Milliseconds */
        time_online?: number
/** Blockchain Transaction Id */
        transaction_id: string
/** Blockchain Transaction Vout */
        transaction_vout: number
/** Unsettled Balance Tokens */
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
/** Only Return Breach Close Channels */
      is_breach_close?: boolean
/** Only Return Cooperative Close Channels */
      is_cooperative_close?: boolean
/** Only Return Funding Canceled Channels */
      is_funding_cancel?: boolean
/** Only Return Local Force Close Channels */
      is_local_force_close?: boolean
/** Only Return Remote Force Close Channels */
      is_remote_force_close?: boolean
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Closed Channel Capacity Tokens */
        capacity: number
/** Channel Balance Output Spent By Tx Id */
        close_balance_spent_by?: string
/** Channel Balance Close Tx Output Index */
        close_balance_vout?: number
        close_payments: [{
/** Payment Is Outgoing */
          is_outgoing: boolean
/** Payment Is Claimed With Preimage */
          is_paid: boolean
/** Payment Resolution Is Pending */
          is_pending: boolean
/** Payment Timed Out And Went Back To Payer */
          is_refunded: boolean
/** Close Transaction Spent By Transaction Id Hex */
          spent_by?: string
/** Associated Tokens */
          tokens: number
/** Transaction Id Hex */
          transaction_id: string
/** Transaction Output Index */
          transaction_vout: number
        }]
/** Channel Close Confirmation Height */
        close_confirm_height?: number
/** Closing Transaction Id Hex */
        close_transaction_id?: string
/** Channel Close Final Local Balance Tokens */
        final_local_balance: number
/** Closed Channel Timelocked Tokens */
        final_time_locked_balance: number
/** Closed Standard Format Channel Id */
        id?: string
/** Is Breach Close */
        is_breach_close: boolean
/** Is Cooperative Close */
        is_cooperative_close: boolean
/** Is Funding Cancelled Close */
        is_funding_cancel: boolean
/** Is Local Force Close */
        is_local_force_close: boolean
/** Channel Was Closed By Channel Peer */
        is_partner_closed?: boolean
/** Channel Was Initiated By Channel Peer */
        is_partner_initiated?: boolean
/** Is Remote Force Close */
        is_remote_force_close: boolean
/** Partner Public Key Hex */
        partner_public_key: string
/** Channel Funding Transaction Id Hex */
        transaction_id: string
/** Channel Funding Output Index */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Maximum Updates Per Session */
      max_session_update_count: number
/** Sweep Tokens per Virtual Byte */
      sweep_tokens_per_vbyte: number
/** Total Backups Made Count */
      backups_count: number
/** Total Backup Failures Count */
      failed_backups_count: number
/** Finished Updated Sessions Count */
      finished_sessions_count: number
/** As Yet Unacknowledged Backup Requests Count */
      pending_backups_count: number
/** Total Backup Sessions Starts Count */
      sessions_count: number
      towers: [{
/** Tower Can Be Used For New Sessions */
        is_active: boolean
/** Identity Public Key Hex */
        public_key: string
        sessions: [{
/** Total Successful Backups Made Count */
          backups_count: number
/** Backups Limit */
          max_backups_count: number
/** Backups Pending Acknowledgement Count */
          pending_backups_count: number
/** Fee Rate in Tokens Per Virtual Byte */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Base Flat Fee Tokens Rounded Up */
        base_fee: number
/** Base Flat Fee Millitokens */
        base_fee_mtokens: string
/** Standard Format Channel Id */
        id: string
/** Channel Funding Transaction Id Hex */
        transaction_id: string
/** Funding Outpoint Output Index */
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
/** From Public Key Hex */
      from: string
/** Authenticated */
      lnd: LND
/** Millitokens To Send */
      mtokens: string
/** To Public Key Hex */
      to: string
    }

    @returns via cbk or Promise
    {
/** Success Confidence Score Out Of One Million */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      nodes: [{
        peers: [{
/** Failed to Forward Tokens */
          failed_tokens?: number
/** Forwarded Tokens */
          forwarded_tokens?: number
          last_failed_forward_at?: <Failed Forward At ISO-8601 Date string>
/** Forwarded At ISO 8601 Date */
          last_forward_at?: string
/** To Public Key Hex */
          to_public_key: string
        }]
/** Node Identity Public Key Hex */
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
/** Get Only Payments Forwarded At Or After ISO 8601 Date */
      after?: string
/** Get Only Payments Forwarded Before ISO 8601 Date */
      before?: string
/** Page Result Limit */
      limit?: number
/** Authenticated */
      lnd: LND
/** Opaque Paging Token */
      token?: string
    }

    @returns via cbk or Promise
    {
      forwards: [{
/** Forward Record Created At ISO 8601 Date */
        created_at: string
/** Fee Tokens Charged */
        fee: number
/** Approximated Fee Millitokens Charged */
        fee_mtokens: string
/** Incoming Standard Format Channel Id */
        incoming_channel: string
/** Forwarded Millitokens */
        mtokens: string
/** Outgoing Standard Format Channel Id */
        outgoing_channel: string
/** Forwarded Tokens */
        tokens: number
      }]
/** Contine With Opaque Paging Token */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Best Chain Hash Hex */
      current_block_hash: string
/** Best Chain Height */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Node Identity Public Key Hex */
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
/** Payment Hash Id Hex */
      id: string
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Fallback Chain Address */
      chain_address?: string
/** CLTV Delta */
      cltv_delta: number
/** Settled at ISO 8601 Date */
      confirmed_at?: string
/** ISO 8601 Date */
      created_at: string
/** Description */
      description: string
/** Description Hash Hex */
      description_hash?: string
/** ISO 8601 Date */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required To Pay */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Payment Hash */
      id: string
/** Invoice is Canceled */
      is_canceled?: boolean
/** Invoice is Confirmed */
      is_confirmed: boolean
/** HTLC is Held */
      is_held?: boolean
/** Invoice is Private */
      is_private: boolean
/** Invoice is Push Payment */
      is_push?: boolean
      payments: [{
/** Payment Settled At ISO 8601 Date */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date */
        created_at: string
/** Payment Held Since Block Height */
        created_height: number
/** Incoming Payment Through Channel Id */
        in_channel: string
/** Payment is Canceled */
        is_canceled: boolean
/** Payment is Confirmed */
        is_confirmed: boolean
/** Payment is Held */
        is_held: boolean
        messages: [{
/** Message Type number */
          type: string
/** Raw Value Hex */
          value: string
        }]
/** Incoming Payment Millitokens */
        mtokens: string
/** Pending Payment Channel HTLC Index */
        pending_index?: number
/** Payment Tokens */
        tokens: number
      }]
/** Received Tokens */
      received: number
/** Received Millitokens */
      received_mtokens: string
/** Bolt 11 Invoice */
      request?: string
/** Secret Preimage Hex */
      secret: string
/** Tokens */
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
/** Page Result Limit */
      limit?: number
/** Authenticated */
      lnd: LND
/** Opaque Paging Token */
      token?: string
    }

    @returns via cbk or Promise
    {
      invoices: [{
/** Fallback Chain Address */
        chain_address?: string
/** Settled at ISO 8601 Date */
        confirmed_at?: string
/** ISO 8601 Date */
        created_at: string
/** Description */
        description: string
/** Description Hash Hex */
        description_hash?: string
/** ISO 8601 Date */
        expires_at: string
        features: [{
/** BOLT 09 Feature Bit */
          bit: number
/** Feature is Known */
          is_known: boolean
/** Feature Support is Required To Pay */
          is_required: boolean
/** Feature Type */
          type: string
        }]
/** Payment Hash */
        id: string
/** Invoice is Canceled */
        is_canceled?: boolean
/** Invoice is Confirmed */
        is_confirmed: boolean
/** HTLC is Held */
        is_held?: boolean
/** Invoice is Private */
        is_private: boolean
/** Invoice is Push Payment */
        is_push?: boolean
        payments: [{
/** Payment Settled At ISO 8601 Date */
          confirmed_at?: string
/** Payment Held Since ISO 860 Date */
          created_at: string
/** Payment Held Since Block Height */
          created_height: number
/** Incoming Payment Through Channel Id */
          in_channel: string
/** Payment is Canceled */
          is_canceled: boolean
/** Payment is Confirmed */
          is_confirmed: boolean
/** Payment is Held */
          is_held: boolean
          messages: [{
/** Message Type number */
            type: string
/** Raw Value Hex */
            value: string
          }]
/** Incoming Payment Millitokens */
          mtokens: string
/** Pending Payment Channel HTLC Index */
          pending_index?: number
/** Payment Tokens */
          tokens: number
/** Total Millitokens */
          total_mtokens?: string
        }]
/** Received Tokens */
        received: number
/** Received Millitokens */
        received_mtokens: string
/** Bolt 11 Invoice */
        request?: string
/** Secret Preimage Hex */
        secret: string
/** Tokens */
        tokens: number
      }]
/** Next Opaque Paging Token */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      methods: [{
/** Method Endpoint Path */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      nodes: [{
/** Betweenness Centrality */
        betweenness: number
/** Normalized Betweenness Centrality */
        betweenness_normalized: number
/** Node Public Key Hex */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      channels: [{
/** Channel Capacity Tokens */
        capacity: number
/** Standard Format Channel Id */
        id: string
        policies: [{
/** Bae Fee Millitokens */
          base_fee_mtokens?: string
/** CLTV Height Delta */
          cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
          fee_rate?: number
/** Edge is Disabled */
          is_disabled?: boolean
/** Maximum HTLC Millitokens */
          max_htlc_mtokens?: string
/** Minimum HTLC Millitokens */
          min_htlc_mtokens?: string
/** Public Key */
          public_key: string
/** Last Update Epoch ISO 8601 Date */
          updated_at?: string
        }]
/** Funding Transaction Id */
        transaction_id: string
/** Funding Transaction Output Index */
        transaction_vout: number
/** Last Update Epoch ISO 8601 Date */
        updated_at?: string
      }]
      nodes: [{
/** Name */
        alias: string
/** Hex Encoded Color */
        color: string
        features: [{
/** BOLT 09 Feature Bit */
          bit: number
/** Feature is Known */
          is_known: boolean
/** Feature Support is Required */
          is_required: boolean
/** Feature Type */
          type: string
        }]
/** Node Public Key */
        public_key: string
/** Network Address and Port */
        sockets: string
/** Last Updated ISO 8601 Date */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Tokens */
      average_channel_size: number
/** Channels Count */
      channel_count: number
/** Tokens */
      max_channel_size: number
/** Median Channel Tokens */
      median_channel_size: number
/** Tokens */
      min_channel_size: number
/** Node Count */
      node_count: number
/** Channel Edge Count */
      not_recently_updated_policy_count: number
/** Total Capacity */
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
/** Omit Channels from Node */
      is_omitting_channels?: boolean
/** Authenticated */
      lnd: LND
/** Node Public Key Hex */
      public_key: string
    }

    @returns via cbk or Promise
    {
/** Node Alias */
      alias: string
/** Node Total Capacity Tokens */
      capacity: number
/** Known Node Channels */
      channel_count: number
      channels?: [{
/** Maximum Tokens */
        capacity: number
/** Standard Format Channel Id */
        id: string
        policies: [{
/** Base Fee Millitokens */
          base_fee_mtokens?: string
/** Locktime Delta */
          cltv_delta?: number
/** Fees Charged Per Million Millitokens */
          fee_rate?: number
/** Channel Is Disabled */
          is_disabled?: boolean
/** Maximum HTLC Millitokens Value */
          max_htlc_mtokens?: string
/** Minimum HTLC Millitokens Value */
          min_htlc_mtokens?: string
/** Node Public Key */
          public_key: string
/** Policy Last Updated At ISO 8601 Date */
          updated_at?: string
        }]
/** Transaction Id Hex */
        transaction_id: string
/** Transaction Output Index */
        transaction_vout: number
/** Channel Last Updated At ISO 8601 Date */
        updated_at?: string
      }]
/** RGB Hex Color */
      color: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required */
        is_required: boolean
/** Feature Type */
        type: string
      }]
      sockets: [{
/** Host and Port */
        socket: string
/** Socket Type */
        type: string
      }]
/** Last Known Update ISO 8601 Date */
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
/** Payment Preimage Hash Hex */
      id: string
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      failed?: {
/** Failed Due To Lack of Balance */
        is_insufficient_balance: boolean
/** Failed Due to Payment Rejected At Destination */
        is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout */
        is_pathfinding_timeout: boolean
/** Failed Due to Absence of Path Through Graph */
        is_route_not_found: boolean
      }
/** Payment Is Settled */
      is_confirmed?: boolean
/** Payment Is Failed */
      is_failed?: boolean
/** Payment Is Pending */
      is_pending?: boolean
      payment?: {
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Routing Fee Tokens */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forwarded Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
/** Payment Hash Hex */
        id: string
/** Total Millitokens Paid */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Tokens Rounded Up */
        safe_tokens: number
/** Payment Preimage Hex */
        secret: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens Paid */
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
/** Page Result Limit */
      limit?: number
/** Authenticated */
      lnd: LND
/** Opaque Paging Token */
      token?: string
    }

    @returns via cbk or Promise
    {
      payments: [{
        attempts: [{
          failure?: {
/** Error Type Code */
            code: number
            details?: {
/** Standard Format Channel Id */
              channel?: string
/** Error Associated Block Height */
              height?: number
/** Failed Hop Index */
              index?: number
/** Error Millitokens */
              mtokens?: string
              policy?: {
/** Base Fee Millitokens */
                base_fee_mtokens: string
/** Locktime Delta */
                cltv_delta: number
/** Fees Charged Per Million Tokens */
                fee_rate: number
/** Channel is Disabled */
                is_disabled?: boolean
/** Maximum HLTC Millitokens Value */
                max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value */
                min_htlc_mtokens: string
/** Updated At ISO 8601 Date */
                updated_at: string
              }
/** Error CLTV Timeout Height */
              timeout_height?: number
              update?: {
/** Chain Id Hex */
                chain: string
/** Channel Flags */
                channel_flags: number
/** Extra Opaque Data Hex */
                extra_opaque_data: string
/** Message Flags */
                message_flags: number
/** Channel Update Signature Hex */
                signature: string
              }
            }
/** Error Message */
            message: string
          }
/** Payment Attempt Succeeded */
          is_confirmed: boolean
/** Payment Attempt Failed */
          is_failed: boolean
/** Payment Attempt is Waiting For Resolution */
          is_pending: boolean
          route: {
/** Route Fee Tokens */
            fee: number
/** Route Fee Millitokens */
            fee_mtokens: string
            hops: [{
/** Standard Format Channel Id */
              channel: string
/** Channel Capacity Tokens */
              channel_capacity: number
/** Fee */
              fee: number
/** Fee Millitokens */
              fee_mtokens: string
/** Forward Tokens */
              forward: number
/** Forward Millitokens */
              forward_mtokens: string
/** Forward Edge Public Key Hex */
              public_key?: string
/** Timeout Block Height */
              timeout?: number
            }]
            mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex */
            payment?: string
/** Timeout Block Height */
            timeout: number
            tokens: <Total Fee-Inclusive Tokens number>
/** Total Millitokens */
            total_mtokens?: string
          }
        }]
        created_at: <Payment at ISO-8601 Date string>
/** Destination Node Public Key Hex */
        destination: string
/** Paid Routing Fee Rounded Down Tokens */
        fee: number
/** Paid Routing Fee in Millitokens */
        fee_mtokens: string
/** First Route Hop Public Key Hex */
        hops: string
/** Payment Preimage Hash */
        id: string
/** Payment Add Index */
        index?: number
/** Payment is Confirmed */
        is_confirmed: boolean
/** Transaction Is Outgoing */
        is_outgoing: boolean
/** Millitokens Sent to Destination */
        mtokens: string
/** BOLT 11 Payment Request */
        request?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Tokens Rounded Up */
        safe_tokens: number
/** Payment Preimage Hex */
        secret: string
/** Rounded Down Tokens Sent to Destination */
        tokens: number
      }]
/** Next Opaque Paging Token */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      peers: [{
/** Bytes Received */
        bytes_received: number
/** Bytes Sent */
        bytes_sent: number
        features: [{
/** BOLT 09 Feature Bit */
          bit: number
/** Feature is Known */
          is_known: boolean
/** Feature Support is Required */
          is_required: boolean
/** Feature Type */
          type: string
        }]
/** Is Inbound Peer */
        is_inbound: boolean
/** Is Syncing Graph Data */
        is_sync_peer?: boolean
/** Peer Last Reconnected At ISO 8601 Date */
        last_reconnected?: string
/** Ping Latency Milliseconds */
        ping_time: number
/** Node Identity Public Key */
        public_key: string
/** Count of Reconnections Over Time */
        reconnection_rate?: number
/** Network Address And Port */
        socket: string
/** Amount Received Tokens */
        tokens_received: number
/** Amount Sent Tokens */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Pending Chain Balance Tokens */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      pending_channels: [{
/** Channel Closing Transaction Id */
        close_transaction_id?: string
/** Channel Is Active */
        is_active: boolean
/** Channel Is Closing */
        is_closing: boolean
/** Channel Is Opening */
        is_opening: boolean
/** Channel Partner Initiated Channel */
        is_partner_initiated?: boolean
/** Channel Local Tokens Balance */
        local_balance: number
/** Channel Local Reserved Tokens */
        local_reserve: number
/** Channel Peer Public Key */
        partner_public_key: string
/** Tokens Pending Recovery */
        pending_balance?: number
        pending_payments?: [{
/** Payment Is Incoming */
          is_incoming: boolean
/** Payment Timelocked Until Height */
          timelock_height: number
/** Payment Tokens */
          tokens: number
/** Payment Transaction Id */
          transaction_id: string
/** Payment Transaction Vout */
          transaction_vout: number
        }]
/** Tokens Received */
        received: number
/** Tokens Recovered From Close */
        recovered_tokens?: number
/** Remote Tokens Balance */
        remote_balance: number
/** Channel Remote Reserved Tokens */
        remote_reserve: number
/** Send Tokens */
        sent: number
/** Pending Tokens Block Height Timelock */
        timelock_expiration?: number
/** Funding Transaction Fee Tokens */
        transaction_fee?: number
/** Channel Funding Transaction Id */
        transaction_id: string
/** Channel Funding Transaction Vout */
        transaction_vout: number
/** Funding Transaction Weight */
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
/** Key Family */
      family: number
/** Key Index */
      index?: number
/** Authenticated API */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Key Index */
      index: number
/** Public Key Hex */
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
/** Starting Hex Serialized Public */
      from?: Key
      hops: [{
/** Forward Millitokens */
        forward_mtokens: string
/** Forward Edge Public Key Hex */
        public_key: string
      }]
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Confidence Score Out Of One Million */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Authenticated */
      lnd: LND
/** Millitokens to Send */
      mtokens?: string
/** Outgoing Channel Id */
      outgoing_channel?: string
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Payment Identifier Hex */
      payment?: string
/** Public Key Hex */
      public_keys: string
/** Tokens to Send */
      tokens?: number
/** Payment Total Millitokens */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route: {
/** Route Fee Tokens */
        fee: number
/** Route Fee Millitokens */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Forward Edge Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Tokens Rounded Up */
        safe_tokens: number
/** Route Timeout Height */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens number>
/** Payment Total Millitokens */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Final Send Destination Hex Encoded Public Key */
      destination: string
      features?: [{
/** Feature Bit */
        bit: number
      }]
      ignore?: [{
/** Channel Id */
        channel?: string
/** Public Key Hex */
        from_public_key: string
/** To Public Key Hex */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex */
      incoming_peer?: string
/** Ignore Past Failures */
      is_ignoring_past_failures?: boolean
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens */
      max_fee?: number
/** Maximum Fee Millitokens */
      max_fee_mtokens?: string
/** Max CLTV Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number */
        type: string
/** Message To Final Destination Raw Value Hex Encoded */
        value: string
      }]
/** Tokens to Send */
      mtokens?: string
/** Outgoing Channel Id */
      outgoing_channel?: string
/** Payment Identifier Hex */
      payment?: Strimng
      routes?: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** Channel Capacity Tokens */
        channel_capacity?: number
/** CLTV Delta Blocks */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Starting Node Public Key Hex */
      start?: string
/** Tokens */
      tokens?: number
/** Total Millitokens of Shards */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route?: {
/** Route Confidence Score Out Of One Million */
        confidence?: number
/** Route Fee Tokens */
        fee: number
/** Route Fee Millitokens */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Forward Edge Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Tokens Rounded Up */
        safe_tokens: number
/** Route Timeout Height */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      transactions: [{
/** Block Hash */
        block_id?: string
/** Confirmation Count */
        confirmation_count?: number
/** Confirmation Block Height */
        confirmation_height?: number
/** Created ISO 8601 Date */
        created_at: string
/** Fees Paid Tokens */
        fee?: number
/** Transaction Id */
        id: string
/** Is Confirmed */
        is_confirmed: boolean
/** Transaction Outbound */
        is_outgoing: boolean
/** Address */
        output_addresses: string
        spends: [{
/** Output Tokens */
          tokens?: number
/** Spend Transaction Id Hex */
          transaction_id: string
/** Spend Transaction Output Index */
          transaction_vout: number
        }]
/** Tokens Including Fee */
        tokens: number
/** Raw Transaction Hex */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      tower?: {
/** Watchtower Server Public Key Hex */
        public_key: string
/** Socket */
        sockets: string
/** Watchtower External URI */
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
/** Authenticated */
      lnd: LND
/** Maximum Confirmations */
      max_confirmations?: number
/** Minimum Confirmations */
      min_confirmations?: number
    }

    @returns via cbk or Promise
    {
      utxos: [{
/** Chain Address */
        address: string
/** Chain Address Format */
        address_format: string
/** Confirmation Count */
        confirmation_count: number
/** Output Script Hex */
        output_script: string
/** Unspent Tokens */
        tokens: number
/** Transaction Id Hex */
        transaction_id: string
/** Transaction Output Index */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Active Channels Count */
      active_channels_count: number
/** Node Alias */
      alias: string
/** Chain Id Hex */
      chains: string
/** Node Color */
      color: string
/** Best Chain Hash Hex */
      current_block_hash: string
/** Best Chain Height */
      current_block_height: number
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Is Synced To Chain */
      is_synced_to_chain: boolean
/** Latest Known Block At Date */
      latest_block_at: string
/** Peer Count */
      peers_count: number
/** Pending Channels Count */
      pending_channels_count: number
/** Public Key */
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
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Build Tag */
      build_tags: string
/** Commit SHA1 160 Bit Hash Hex */
      commit_hash: string
/** Is Autopilot RPC Enabled */
      is_autopilotrpc_enabled: boolean
/** Is Chain RPC Enabled */
      is_chainrpc_enabled: boolean
/** Is Invoices RPC Enabled */
      is_invoicesrpc_enabled: boolean
/** Is Sign RPC Enabled */
      is_signrpc_enabled: boolean
/** Is Wallet RPC Enabled */
      is_walletrpc_enabled: boolean
/** Is Watchtower Server RPC Enabled */
      is_watchtowerrpc_enabled: boolean
/** Is Watchtower Client RPC Enabled */
      is_wtclientrpc_enabled: boolean
/** Recognized LND Version */
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
/** Macaroon Id Positive Numeric */
      id?: string
/** Can Add or Remove Peers */
      is_ok_to_adjust_peers?: boolean
/** Can Make New Addresses */
      is_ok_to_create_chain_addresses?: boolean
/** Can Create Lightning Invoices */
      is_ok_to_create_invoices?: boolean
/** Can Create Macaroons */
      is_ok_to_create_macaroons?: boolean
/** Can Derive Public Keys */
      is_ok_to_derive_keys?: boolean
/** Can List Access Ids */
      is_ok_to_get_access_ids?: boolean
/** Can See Chain Transactions */
      is_ok_to_get_chain_transactions?: boolean
/** Can See Invoices */
      is_ok_to_get_invoices?: boolean
/** Can General Graph and Wallet Information */
      is_ok_to_get_wallet_info?: boolean
/** Can Get Historical Lightning Transactions */
      is_ok_to_get_payments?: boolean
/** Can Get Node Peers Information */
      is_ok_to_get_peers?: boolean
/** Can Send Funds or Edit Lightning Payments */
      is_ok_to_pay?: boolean
/** Can Revoke Access Ids */
      is_ok_to_revoke_access_ids?: boolean
/** Can Send Coins On Chain */
      is_ok_to_send_to_chain_addresses?: boolean
/** Can Sign Bytes From Node Keys */
      is_ok_to_sign_bytes?: boolean
/** Can Sign Messages From Node Key */
      is_ok_to_sign_messages?: boolean
/** Can Terminate Node or Change Operation Mode */
      is_ok_to_stop_daemon?: boolean
/** Can Verify Signatures of Bytes */
      is_ok_to_verify_bytes_signatures?: boolean
/** Can Verify Messages From Node Keys */
      is_ok_to_verify_messages?: boolean
/** Authenticated */
      lnd: LND
      permissions]: [<Entity:Action string>?
    }

    @returns via cbk or Promise
    {
/** Base64 Encoded Macaroon */
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
/** Bind to Address */
      bind?: string
/** LND Cert Base64 */
      cert?: string
/** Log */
      log: Function
/** Router Path */
      path: string
/** Listen Port */
      port: number
/** LND Socket */
      socket: string
/** Log Write Stream */
      stream: Object
    }

    @returns
    {
/** Express Application */
      app: Object
/** Web Server */
      server: Object
/** WebSocket Server */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Pay to Node with Public Key Hex */
      destination: string
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens To Pay */
      max_fee?: number
/** Maximum Expiration CLTV Timeout Height */
      max_timeout_height?: number
/** Pay Out of Outgoing Standard Format Channel Id */
      outgoing_channel?: string
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
      routes?: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Paying Tokens */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Payment Is Successfully Tested Within Constraints */
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
/** Lock Identifier Hex */
      id?: string
/** Authenticated */
      lnd: LND
/** Unspent Transaction Id Hex */
      transaction_id: string
/** Unspent Transaction Output Index */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Lock Expires At ISO 8601 Date */
      expires_at: string
/** Locking Id Hex */
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
/** Chain Fee Tokens Per VByte */
      chain_fee_tokens_per_vbyte?: number
/** Restrict Cooperative Close To Address */
      cooperative_close_address?: string
/** Tokens to Gift To Partner */
      give_tokens?: number
/** Channel is Private */
      is_private?: boolean
/** Authenticated */
      lnd: LND
/** Local Tokens */
      local_tokens: number
/** Spend UTXOs With Minimum Confirmations */
      min_confirmations?: number
/** Minimum HTLC Millitokens */
      min_htlc_mtokens?: string
/** Public Key Hex */
      partner_public_key: string
/** Peer Output CSV Delay */
      partner_csv_delay?: number
      partner_socket?: <Peer Connection Host:Port string>
    }

    @returns via cbk or Promise
    {
/** Funding Transaction Id */
      transaction_id: string
/** Funding Transaction Output Index */
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
/** Channel Capacity Tokens */
        capacity: number
/** Restrict Coop Close To Address */
        cooperative_close_address?: string
/** Tokens to Gift To Partner */
        give_tokens?: number
/** Channel is Private */
        is_private?: boolean
/** Minimum HTLC Millitokens */
        min_htlc_mtokens?: string
/** Public Key Hex */
        partner_public_key: string
/** Peer Output CSV Delay */
        partner_csv_delay?: number
        partner_socket?: <Peer Connection Host:Port string>
      }]
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
      pending: [{
/** Address To Send To */
        address: string
/** Pending Channel Id Hex */
        id: string
/** Tokens to Send */
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
/** BOLT 11 Payment Request */
      request: string
    }

    @throws
/** ExpectedLnPrefix */
    Error
/** ExpectedPaymentHash */
    Error
/** ExpectedPaymentRequest */
    Error
/** ExpectedValidHrpForPaymentRequest */
    Error
/** FailedToParsePaymentRequestDescriptionHash */
    Error
/** FailedToParsePaymentRequestFallbackAddress */
    Error
/** FailedToParsePaymentRequestPaymentHash */
    Error
/** InvalidDescriptionInPaymentRequest */
    Error
/** InvalidOrMissingSignature */
    Error
/** InvalidPaymentHashByteLength */
    Error
/** InvalidPaymentRequestPrefix */
    Error
/** UnknownCurrencyCodeInPaymentRequest */
    Error

    @returns
    {
/** Chain Address */
      chain_addresses]: [string
/** CLTV Delta */
      cltv_delta: number
/** Invoice Creation Date ISO 8601 */
      created_at: string
/** Description */
      description?: string
/** Description Hash Hex */
      description_hash?: string
/** Public Key */
      destination: string
/** ISO 8601 Date */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature Support is Required To Pay */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Payment Request Hash */
      id: string
/** Invoice is Expired */
      is_expired: boolean
      mtokens?: <Requested Milli-Tokens Value string> (can exceed number limit)
/** Network Name */
      network: string
/** Payment Identifier Hex Encoded */
      payment?: string
      routes?: [[{
/** Base Fee Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** Final CLTV Expiration Blocks Delta */
        cltv_delta?: number
/** Fee Rate Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Requested Tokens Rounded Up */
      safe_tokens?: number
/** Requested Chain Tokens */
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
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Additional Fee Tokens To Pay */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths */
      max_paths?: number
/** Max CLTV Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Pay Through Outbound Standard Channel Id */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids */
      outgoing_channels]: [string
      path?: {
/** Payment Hash Hex */
        id: string
        routes: [{
/** Total Fee Tokens To Pay */
          fee: number
/** Total Fee Millitokens To Pay */
          fee_mtokens: string
          hops: [{
/** Standard Format Channel Id */
            channel: string
/** Channel Capacity Tokens */
            channel_capacity: number
/** Fee */
            fee: number
/** Fee Millitokens */
            fee_mtokens: string
/** Forward Tokens */
            forward: number
/** Forward Millitokens */
            forward_mtokens: string
/** Public Key Hex */
            public_key?: string
/** Timeout Block Height */
            timeout: number
          }]
          messages?: [{
/** Message Type number */
            type: string
/** Message Raw Value Hex Encoded */
            value: string
          }]
/** Total Millitokens To Pay */
          mtokens: string
/** Payment Identifier Hex */
          payment?: string
/** Expiration Block Height */
          timeout: number
/** Total Tokens To Pay */
          tokens: number
        }]
      }
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request */
      request?: string
/** Total Tokens To Pay to Payment Request */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Fee Paid Tokens */
      fee: number
/** Fee Paid Millitokens */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Hop Channel Capacity Tokens */
        channel_capacity: number
/** Hop Forward Fee Millitokens */
        fee_mtokens: string
/** Hop Forwarded Millitokens */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Is Confirmed */
      is_confirmed: boolean
/** Is Outoing */
      is_outgoing: boolean
/** Total Millitokens Sent */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Secret Preimage Hex */
      secret: string
/** Total Tokens Sent */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Destination Public Key */
      destination: string
      features?: [{
/** Feature Bit */
        bit: number
      }]
/** Payment Request Hash Hex */
      id?: string
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens To Pay */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths */
      max_paths?: number
/** Maximum Expiration CLTV Timeout Height */
      max_timeout_height?: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Pay Out of Outgoing Channel Id */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
      routes: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Tokens To Pay */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens Paid Rounded Down */
      fee: number
/** Total Fee Millitokens Paid */
      fee_mtokens: string
      hops: [{
/** First Route Standard Format Channel Id */
        channel: string
/** First Route Channel Capacity Tokens */
        channel_capacity: number
/** First Route Fee Tokens Rounded Down */
        fee: number
/** First Route Fee Millitokens */
        fee_mtokens: string
/** First Route Forward Millitokens */
        forward_mtokens: string
/** First Route Public Key Hex */
        public_key: string
/** First Route Timeout Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Total Millitokens Paid */
      mtokens: string
      paths: [{
/** Total Fee Millitokens Paid */
        fee_mtokens: string
        hops: [{
/** First Route Standard Format Channel Id */
          channel: string
/** First Route Channel Capacity Tokens */
          channel_capacity: number
/** First Route Fee Tokens Rounded Down */
          fee: number
/** First Route Fee Millitokens */
          fee_mtokens: string
/** First Route Forward Millitokens */
          forward_mtokens: string
/** First Route Public Key Hex */
          public_key: string
/** First Route Timeout Block Height */
          timeout: number
        }]
/** Total Millitokens Paid */
        mtokens: string
      }]
/** Total Fee Tokens Paid Rounded Up */
      safe_fee: number
      safe_tokens: <Total Tokens Paid, Rounded Up number>
/** Payment Preimage Hex */
      secret: string
/** Expiration Block Height */
      timeout: number
/** Total Tokens Paid Rounded Down */
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
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens To Pay */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths */
      max_paths?: number
/** Maximum Height of Payment Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Pay Out of Outgoing Channel Id */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request */
      request: string
/** Tokens To Pay */
      tokens?: number
    }

    @returns via cbk or Promise
    {
/** Total Fee Tokens Paid Rounded Down */
      fee: number
/** Total Fee Millitokens Paid */
      fee_mtokens: string
      hops: [{
/** First Route Standard Format Channel Id */
        channel: string
/** First Route Channel Capacity Tokens */
        channel_capacity: number
/** First Route Fee Tokens Rounded Down */
        fee: number
/** First Route Fee Millitokens */
        fee_mtokens: string
/** First Route Forward Millitokens */
        forward_mtokens: string
/** First Route Public Key Hex */
        public_key: string
/** First Route Timeout Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Total Millitokens Paid */
      mtokens: string
      paths: [{
/** Total Fee Millitokens Paid */
        fee_mtokens: string
        hops: [{
/** First Route Standard Format Channel Id */
          channel: string
/** First Route Channel Capacity Tokens */
          channel_capacity: number
/** First Route Fee Tokens Rounded Down */
          fee: number
/** First Route Fee Millitokens */
          fee_mtokens: string
/** First Route Forward Millitokens */
          forward_mtokens: string
/** First Route Public Key Hex */
          public_key: string
/** First Route Timeout Block Height */
          timeout: number
        }]
/** Total Millitokens Paid */
        mtokens: string
      }]
/** Total Fee Tokens Paid Rounded Up */
      safe_fee: number
      safe_tokens: <Total Tokens Paid, Rounded Up number>
/** Payment Preimage Hex */
      secret: string
/** Expiration Block Height */
      timeout: number
/** Total Tokens Paid Rounded Down */
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
/** Payment Hash Hex */
      id?: string
/** Authenticated */
      lnd: LND
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
      routes: [{
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key?: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
      }]
    }

    @returns via cbk or Promise
    {
      failures: [[
/** Failure Code */
        number
/** Failure Code Message */
        string
/** Failure Code Details */
        Object
      ]]
/** Fee Paid Tokens */
      fee: number
/** Fee Paid Millitokens */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Hop Channel Capacity Tokens */
        channel_capacity: number
/** Hop Forward Fee Millitokens */
        fee_mtokens: string
/** Hop Forwarded Millitokens */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Is Confirmed */
      is_confirmed: boolean
/** Is Outoing */
      is_outgoing: boolean
/** Total Millitokens Sent */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Secret Preimage Hex */
      secret: string
/** Total Tokens Sent Rounded Down */
      tokens: number
    }

    @returns error via cbk or Promise
    [
/** Error Classification Code */
      number
/** Error Type */
      string
      {
        failures: [[
/** Failure Code */
          number
/** Failure Code Message */
          string
/** Failure Code Details */
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
/** Cooperative Close Relative Delay */
      cooperative_close_delay?: number
/** Pending Id Hex */
      id?: string
/** Channel Funding Output Multisig Local Key Index */
      key_index: number
/** Authenticated */
      lnd: LND
/** Channel Funding Partner Multisig Public Key Hex */
      remote_key: string
/** Funding Output Transaction Id Hex */
      transaction_id: string
/** Funding Output Transaction Output Index */
      transaction_vout: number
    }

    @returns via cbk or Promise
    {
/** Pending Channel Id Hex */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Destination Public Key Hex */
      destination: string
      features?: [{
/** Feature Bit */
        bit: number
      }]
      ignore?: [{
/** Channel Id */
        channel?: string
/** Public Key Hex */
        from_public_key: string
/** To Public Key Hex */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex */
      incoming_peer?: string
/** Adjust Probe For Past Routing Failures */
      is_ignoring_past_failures?: boolean
/** Only Route Through Specified Paths */
      is_strict_hints?: boolean
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Height of Payment Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number */
        type: string
/** Message To Final Destination Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Outgoing Channel Id */
      outgoing_channel?: string
/** Time to Spend On A Path Milliseconds */
      path_timeout_ms?: number
/** Payment Identifier Hex */
      payment?: string
/** Probe Timeout Milliseconds */
      probe_timeout_ms?: number
      routes?: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: number
/** Channel Capacity Tokens */
        channel_capacity?: number
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Tokens */
      tokens: number
/** Total Millitokens Across Paths */
      total_mtokens?: string
    }

    @returns via cbk or Promise
    {
      route?: {
/** Route Confidence Score Out Of One Million */
        confidence?: number
/** Route Fee Tokens Rounded Down */
        fee: number
/** Route Fee Millitokens */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Forward Edge Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identifier Hex */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Tokens Rounded Up */
        safe_tokens: number
/** Timeout Block Height */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens Rounded Down number>
/** Total Millitokens */
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
/** Channel Capacity Tokens */
      capacity: number
/** Restrict Cooperative Close To Address */
      cooperative_close_address?: string
/** Cooperative Close Relative Delay */
      cooperative_close_delay?: number
/** Tokens to Gift To Partner */
      give_tokens?: number
/** Pending Channel Id Hex */
      id: string
/** Channel is Private */
      is_private?: boolean
/** Channel Funding Output MultiSig Local Key Index */
      key_index: number
/** Authenticated */
      lnd: LND
/** Public Key Hex */
      partner_public_key: string
/** Channel Funding Partner MultiSig Public Key Hex */
      remote_key: string
/** Funding Output Transaction Id Hex */
      transaction_id: string
/** Funding Output Transaction Output Index */
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
/** Backup Hex */
      backup: string
/** Authenticated */
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
/** Backup Hex */
      backup: string
/** Authenticated */
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
/** Authenticated */
      lnd: LND
/** Public Key Hex */
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
/** Expires At ISO 8601 Date */
      expires_at?: string
/** IP Address */
      ip?: string
/** Base64 Encoded Macaroon */
      macaroon: string
    }

    @throws
    <Error>

    @returns
    {
/** Restricted Base64 Encoded Macaroon */
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
/** Access Token Macaroon Root Id Positive Integer */
      id: string
/** Authenticated */
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
/** Maximum Tokens */
        capacity: number
/** Next Node Public Key Hex */
        destination?: string
/** Standard Format Channel Id */
        id: string
        policies: [{
/** Base Fee Millitokens */
          base_fee_mtokens: string
/** Locktime Delta */
          cltv_delta: number
/** Fees Charged Per Million Tokens */
          fee_rate: number
/** Channel Is Disabled */
          is_disabled: boolean
/** Minimum HTLC Millitokens Value */
          min_htlc_mtokens: string
/** Node Public Key */
          public_key: string
        }]
      }]
/** Final CLTV Delta */
      cltv_delta?: number
/** Destination Public Key Hex */
      destination?: string
/** Current Block Height */
      height: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens To Send */
      mtokens: string
/** Payment Identification Value Hex */
      payment?: string
/** Sum of Shards Millitokens */
      total_mtokens?: string
    }

    @throws
    <Error>

    @returns
    {
      route: {
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key?: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
        mtokens: <Total Fee-Inclusive Millitokens string>
/** Payment Identification Value Hex */
        payment?: string
/** Timeout Block Height */
        timeout: number
        tokens: <Total Fee-Inclusive Tokens number>
/** Sum of Shards Millitokens */
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
/** Destination Chain Address */
      address: string
/** Transaction Label */
      description?: string
/** Chain Fee Tokens Per Virtual Byte */
      fee_tokens_per_vbyte?: number
/** Send All Funds */
      is_send_all?: boolean
/** Authenticated */
      lnd: LND
/** Log */
      log?: Function
/** Confirmations To Wait */
      target_confirmations?: number
/** Tokens To Send */
      tokens: number
/** Minimum Confirmations for UTXO Selection */
      utxo_confirmations?: number
/** Web Socket Server */
      wss]: [Object
    }

    @returns via cbk or Promise
    {
/** Total Confirmations */
      confirmation_count: number
/** Transaction Id Hex */
      id: string
/** Transaction Is Confirmed */
      is_confirmed: boolean
/** Transaction Is Outgoing */
      is_outgoing: boolean
/** Transaction Tokens */
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
/** Transaction Label */
      description?: string
/** Chain Fee Tokens Per Virtual Byte */
      fee_tokens_per_vbyte?: number
/** Authenticated */
      lnd: LND
/** Log */
      log?: Function
      send_to: [{
/** Address */
        address: string
/** Tokens */
        tokens: number
      }]
/** Confirmations To Wait */
      target_confirmations?: number
/** Minimum Confirmations for UTXO Selection */
      utxo_confirmations?: number
/** Web Socket Server */
      wss]: [Object
    }

    @returns via cbk or Promise
    {
/** Total Confirmations */
      confirmation_count: number
/** Transaction Id Hex */
      id: string
/** Transaction Is Confirmed */
      is_confirmed: boolean
/** Transaction Is Outgoing */
      is_outgoing: boolean
/** Transaction Tokens */
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
/** Node Public Key Hex */
        public_key: string
/** Score */
        score: number
      }]
/** Enable Autopilot */
      is_enabled?: boolean
/** Authenticated */
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
/** Authenticated */
      lnd: LND
/** Payment Preimage Hex */
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
/** Key Family */
      key_family: number
/** Key Index */
      key_index: number
/** Authenticated */
      lnd: LND
/** Bytes To Hash and Sign Hex Encoded */
      preimage: string
    }

    @returns via cbk or Promise
    {
/** Signature Hex */
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
/** Authenticated */
      lnd: LND
/** Message */
      message: string
    }

    @returns via cbk or Promise
    {
/** Signature */
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
/** Authenticated */
      lnd: LND
/** Funded PSBT Hex */
      psbt: string
    }

    @returns via cbk or Promise
    {
/** Finalized PSBT Hex */
      psbt: string
/** Signed Raw Transaction Hex */
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
/** Key Family */
        key_family: number
/** Key Index */
        key_index: number
/** Output Script Hex */
        output_script: string
/** Output Tokens */
        output_tokens: number
/** Sighash Type */
        sighash: number
/** Input Index To Sign */
        vin: number
/** Witness Script Hex */
        witness_script: string
      }]
/** Authenticated */
      lnd: LND
/** Unsigned Transaction Hex */
      transaction: string
    }

    @returns via cbk or Promise
    {
/** Signature Hex */
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
/** Authenticated */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'backup'
    {
/** Backup Hex */
      backup: string
      channels: [{
/** Backup Hex */
        backup: string
/** Funding Transaction Id Hex */
        transaction_id: string
/** Funding Transaction Output Index */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'block'
    {
/** Block Height */
      height: number
/** Block Hash */
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
/** Address */
      bech32_address?: string
/** Chain RPC */
      lnd: LND
/** Minimum Confirmations */
      min_confirmations?: number
/** Minimum Transaction Inclusion Blockchain Height */
      min_height: number
/** Output Script Hex */
      output_script?: string
/** Address */
      p2pkh_address?: string
/** Address */
      p2sh_address?: string
/** Blockchain Transaction Id */
      transaction_id?: string
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'confirmation'
    {
/** Block Hash Hex */
      block: string
/** Block Best Chain Height */
      height: number
/** Raw Transaction Hex */
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
/** Bech32 P2WPKH or P2WSH Address */
      bech32_address?: string
/** Authenticated */
      lnd: LND
/** Minimum Transaction Inclusion Blockchain Height */
      min_height: number
/** Output Script AKA ScriptPub Hex */
      output_script?: string
/** Pay to Public Key Hash Address */
      p2pkh_address?: string
/** Pay to Script Hash Address */
      p2sh_address?: string
/** Blockchain Transaction Id Hex */
      transaction_id?: string
/** Blockchain Transaction Output Index */
      transaction_vout?: number
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'confirmation'
    {
/** Confirmation Block Height */
      height: number
/** Raw Transaction Hex */
      transaction: string
/** Spend Outpoint Index */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'channel_active_changed'
    {
/** Channel Is Active */
      is_active: boolean
/** Channel Funding Transaction Id */
      transaction_id: string
/** Channel Funding Transaction Output Index */
      transaction_vout: number
    }

    @event 'channel_closed'
    {
/** Closed Channel Capacity Tokens */
      capacity: number
/** Channel Balance Output Spent By Tx Id */
      close_balance_spent_by?: string
/** Channel Balance Close Tx Output Index */
      close_balance_vout?: number
/** Channel Close Confirmation Height */
      close_confirm_height?: number
      close_payments: [{
/** Payment Is Outgoing */
        is_outgoing: boolean
/** Payment Is Claimed With Preimage */
        is_paid: boolean
/** Payment Resolution Is Pending */
        is_pending: boolean
/** Payment Timed Out And Went Back To Payer */
        is_refunded: boolean
/** Close Transaction Spent By Transaction Id Hex */
        spent_by?: string
/** Associated Tokens */
        tokens: number
/** Transaction Id Hex */
        transaction_id: string
/** Transaction Output Index */
        transaction_vout: number
      }]
/** Closing Transaction Id Hex */
      close_transaction_id?: string
/** Channel Close Final Local Balance Tokens */
      final_local_balance: number
/** Closed Channel Timelocked Tokens */
      final_time_locked_balance: number
/** Closed Standard Format Channel Id */
      id?: string
/** Is Breach Close */
      is_breach_close: boolean
/** Is Cooperative Close */
      is_cooperative_close: boolean
/** Is Funding Cancelled Close */
      is_funding_cancel: boolean
/** Is Local Force Close */
      is_local_force_close: boolean
/** Channel Was Closed By Channel Peer */
      is_partner_closed?: boolean
/** Channel Was Initiated By Channel Peer */
      is_partner_initiated?: boolean
/** Is Remote Force Close */
      is_remote_force_close: boolean
/** Partner Public Key Hex */
      partner_public_key: string
/** Channel Funding Transaction Id Hex */
      transaction_id: string
/** Channel Funding Output Index */
      transaction_vout: number
    }

    @event 'channel_opened'
    {
/** Channel Token Capacity */
      capacity: number
/** Commit Transaction Fee */
      commit_transaction_fee: number
/** Commit Transaction Weight */
      commit_transaction_weight: number
/** Coop Close Restricted to Address */
      cooperative_close_address?: string
/** Prevent Coop Close Until Height */
      cooperative_close_delay_height?: number
/** Standard Format Channel Id */
      id: string
/** Channel Active */
      is_active: boolean
/** Channel Is Closing */
      is_closing: boolean
/** Channel Is Opening */
      is_opening: boolean
/** Channel Partner Opened Channel */
      is_partner_initiated: boolean
/** Channel Is Private */
      is_private: boolean
/** Remote Key Is Static */
      is_static_remote_key: boolean
/** Local Balance Tokens */
      local_balance: number
/** Local Initially Pushed Tokens */
      local_given?: number
/** Local Reserved Tokens */
      local_reserve: number
/** Channel Partner Public Key */
      partner_public_key: string
      pending_payments: [{
/** Payment Preimage Hash Hex */
        id: string
/** Payment Is Outgoing */
        is_outgoing: boolean
/** Chain Height Expiration */
        timeout: number
/** Payment Tokens */
        tokens: number
      }]
/** Received Tokens */
      received: number
/** Remote Balance Tokens */
      remote_balance: number
/** Remote Initially Pushed Tokens */
      remote_given?: number
/** Remote Reserved Tokens */
      remote_reserve: number
/** Sent Tokens */
      sent: number
/** Blockchain Transaction Id */
      transaction_id: string
/** Blockchain Transaction Vout */
      transaction_vout: number
/** Unsettled Balance Tokens */
      unsettled_balance: number
    }

    @event 'channel_opening'
    {
/** Blockchain Transaction Id Hex */
      transaction_id: string
/** Blockchain Transaction Output Index */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'forward_request`
    {
      accept: () => {}
/** Difference Between Out and In CLTV Height */
      cltv_delta: number
/** Routing Fee Tokens Rounded Down */
      fee: number
/** Routing Fee Millitokens */
      fee_mtokens: string
/** Payment Hash Hex */
      hash: string
/** Inbound Standard Format Channel Id */
      in_channel: string
/** Inbound Channel Payment Id */
      in_payment: number
      messages: [{
/** Message Type number */
        type: string
/** Raw Value Hex */
        value: string
      }]
/** Millitokens to Forward To Next Peer */
      mtokens: string
      onion?: <Hex Serialized Next-Hop Onion Packet To Forward string>
/** Requested Outbound Channel Standard Format Id */
      out_channel: string
/** Reject Forward */
      reject: Function
/** Short Circuit */
      settle: Function
/** CLTV Timeout Height */
      timeout: number
/** Tokens to Forward to Next Peer Rounded Down */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter */
    Object

    @event 'error'
/** Error */
    Object

    @event 'forward'
    {
/** Forward Update At ISO 8601 Date */
      at: string
/** Public Failure Reason */
      external_failure?: string
/** Inbound Standard Format Channel Id */
      in_channel?: string
/** Inbound Channel Payment Id */
      in_payment?: number
/** Private Failure Reason */
      internal_failure?: string
/** Forward Is Confirmed */
      is_confirmed: boolean
/** Forward Is Failed */
      is_failed: boolean
/** Is Receive */
      is_receive: boolean
/** Is Send */
      is_send: boolean
/** Sending Millitokens */
      mtokens?: number
/** Outgoing Standard Format Channel Id */
      out_channel?: string
/** Outgoing Channel Payment Id */
      out_payment?: number
/** Forward Timeout at Height */
      timeout?: number
/** Sending Tokens */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'channel_updated'
    {
/** Channel Base Fee Millitokens */
      base_fee_mtokens: string
/** Channel Capacity Tokens */
      capacity: number
/** Channel CLTV Delta */
      cltv_delta: number
/** Channel Fee Rate In Millitokens Per Million */
      fee_rate: number
/** Standard Format Channel Id */
      id: string
/** Channel Is Disabled */
      is_disabled: boolean
/** Channel Maximum HTLC Millitokens */
      max_htlc_mtokens?: string
/** Channel Minimum HTLC Millitokens */
      min_htlc_mtokens: string
/** Target Public Key */
      public_keys: <Announcing Public Key>, string
/** Channel Transaction Id */
      transaction_id: string
/** Channel Transaction Output Index */
      transaction_vout: number
/** Update Received At ISO 8601 Date */
      updated_at: string
    }

    @event 'channel_closed'
    {
/** Channel Capacity Tokens */
      capacity?: number
/** Channel Close Confirmed Block Height */
      close_height: number
/** Standard Format Channel Id */
      id: string
/** Channel Transaction Id */
      transaction_id?: string
/** Channel Transaction Output Index */
      transaction_vout?: number
/** Update Received At ISO 8601 Date */
      updated_at: string
    }

    @event 'error'
/** Subscription */
    Error

    @event 'node_updated'
    {
/** Node Alias */
      alias: string
/** Node Color */
      color: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Node Public Key */
      public_key: string
/** Network Host And Port */
      sockets]: [string
/** Update Received At ISO 8601 Date */
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
/** Invoice Payment Hash Hex */
      id: string
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event `invoice_updated`
    {
/** Fallback Chain Address */
      chain_address: string
/** Settled at ISO 8601 Date */
      confirmed_at?: string
/** ISO 8601 Date */
      created_at: string
/** Description */
      description: string
/** Description Hash Hex */
      description_hash: string
/** ISO 8601 Date */
      expires_at: string
      features: [{
/** BOLT 09 Feature Bit */
        bit: number
/** Feature is Known */
        is_known: boolean
/** Feature Support is Required To Pay */
        is_required: boolean
/** Feature Type */
        type: string
      }]
/** Payment Hash */
      id: string
/** Invoice is Canceled */
      is_canceled?: boolean
/** Invoice is Confirmed */
      is_confirmed: boolean
/** HTLC is Held */
      is_held?: boolean
/** Invoice is Outgoing */
      is_outgoing: boolean
/** Invoice is Private */
      is_private: boolean
/** Invoiced Millitokens */
      mtokens: string
      payments: [{
/** Payment Settled At ISO 8601 Date */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date */
        created_at: string
/** Payment Held Since Block Height */
        created_height: number
/** Incoming Payment Through Channel Id */
        in_channel: string
/** Payment is Canceled */
        is_canceled: boolean
/** Payment is Confirmed */
        is_confirmed: boolean
/** Payment is Held */
        is_held: boolean
        messages: [{
/** Message Type number */
          type: string
/** Raw Value Hex */
          value: string
        }]
/** Incoming Payment Millitokens */
        mtokens: string
/** Pending Payment Channel HTLC Index */
        pending_index?: number
/** Payment Tokens */
        tokens: number
      }]
/** Received Tokens */
      received: number
/** Received Millitokens */
      received_mtokens: string
/** Bolt 11 Invoice */
      request: string
      routes: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens: number
/** Standard Format Channel Id */
        channel: string
/** CLTV Blocks Delta */
        cltv_delta: number
/** Fee Rate In Millitokens Per Million */
        fee_rate: number
/** Public Key Hex */
        public_key: string
      }]]
/** Secret Preimage Hex */
      secret: string
/** Tokens */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'invoice_updated'
    {
/** Fallback Chain Address */
      chain_address?: string
/** Final CLTV Delta */
      cltv_delta: number
/** Confirmed At ISO 8601 Date */
      confirmed_at?: string
/** Created At ISO 8601 Date */
      created_at: string
/** Description */
      description: string
/** Description Hash Hex */
      description_hash: string
/** Expires At ISO 8601 Date */
      expires_at: string
      features: [{
/** Feature Bit */
        bit: number
/** Is Known Feature */
        is_known: boolean
/** Feature Is Required */
        is_required: boolean
/** Feature Name */
        name: string
      }]
/** Invoice Payment Hash Hex */
      id: string
/** Invoice is Confirmed */
      is_confirmed: boolean
/** Invoice is Outgoing */
      is_outgoing: boolean
/** Invoice is Push Payment */
      is_push?: boolean
      payments: [{
/** Payment Settled At ISO 8601 Date */
        confirmed_at?: string
/** Payment Held Since ISO 860 Date */
        created_at: string
/** Payment Held Since Block Height */
        created_height: number
/** Incoming Payment Through Channel Id */
        in_channel: string
/** Payment is Canceled */
        is_canceled: boolean
/** Payment is Confirmed */
        is_confirmed: boolean
/** Payment is Held */
        is_held: boolean
        messages: [{
/** Message Type number */
          type: string
/** Raw Value Hex */
          value: string
        }]
/** Incoming Payment Millitokens */
        mtokens: string
/** Pending Payment Channel HTLC Index */
        pending_index?: number
/** Payment Tokens */
        tokens: number
/** Total Payment Millitokens */
        total_mtokens?: string
      }]
/** Received Tokens */
      received: number
/** Received Millitokens */
      received_mtokens: string
/** BOLT 11 Payment Request */
      request?: string
/** Payment Secret Hex */
      secret: string
/** Invoiced Tokens */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'channel_request'
    {
/** Accept Request */
      accept: Function
/** Restrict Coop Close To Address */
        cooperative_close_address?: string
/** Required Confirmations Before Channel Open */
        min_confirmations?: number
/** Peer Unilateral Balance Output CSV Delay */
        remote_csv?: number
/** Minimum Tokens Peer Must Keep On Their Side */
        remote_reserve?: number
/** Maximum Slots For Attaching HTLCs */
        remote_max_htlcs?: number
/** Maximum HTLCs Value Millitokens */
        remote_max_pending_mtokens?: string
/** Minimium HTLC Value Millitokens */
        remote_min_htlc_mtokens?: string
      }) -> {}
/** Capacity Tokens */
      capacity: number
/** Chain Id Hex */
      chain: string
/** Commitment Transaction Fee */
      commit_fee_tokens_per_vbyte: number
/** CSV Delay Blocks */
      csv_delay: number
/** Request Id Hex */
      id: string
/** Channel Local Tokens Balance */
      local_balance: number
/** Channel Local Reserve Tokens */
      local_reserve: number
/** Maximum Millitokens Pending In Channel */
      max_pending_mtokens: string
/** Maximum Pending Payments */
      max_pending_payments: number
/** Minimum Chain Output Tokens */
      min_chain_output: number
/** Minimum HTLC Millitokens */
      min_htlc_mtokens: string
/** Peer Public Key Hex */
      partner_public_key: string
/** Reject Request */
      reject: Function
/** 500 Character Limited Rejection Reason */
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
/** Payment Request Hash Hex */
      id: string
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter */
    Object

    @event 'confirmed'
    {
/** Total Fee Millitokens To Pay */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Channel Capacity Tokens */
        channel_capacity: number
/** Routing Fee Tokens */
        fee: number
/** Fee Millitokens */
        fee_mtokens: string
/** Forwarded Tokens */
        forward: number
/** Forward Millitokens */
        forward_mtokens: string
/** Public Key Hex */
        public_key: string
/** Timeout Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Total Millitokens Paid */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Preimage Hex */
      secret: string
/** Expiration Block Height */
      timeout: number
/** Tokens Paid */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance */
      is_insufficient_balance: boolean
/** Failed Due to Payment Rejected At Destination */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout */
      is_pathfinding_timeout: boolean
/** Failed Due to Absence of Path Through Graph */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Destination Public Key */
      destination: string
      features?: [{
/** Feature Bit */
        bit: number
      }]
/** Payment Request Hash Hex */
      id?: string
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens To Pay */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths */
      max_paths?: number
/** Maximum Height of Payment Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Pay Out of Outgoing Channel Id */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
      routes?: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Tokens to Pay */
      tokens?: number
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter */
    Object

    @event 'confirmed'
    {
/** Fee Tokens Paid */
      fee: number
/** Total Fee Millitokens Paid */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Channel Capacity Tokens */
        channel_capacity: number
/** Fee Millitokens */
        fee_mtokens: string
/** Forward Millitokens */
        forward_mtokens: string
/** Public Key Hex */
        public_key: string
/** Timeout Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id?: string
/** Total Millitokens To Pay */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Preimage Hex */
      secret: string
/** Total Tokens Paid Rounded Down */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance */
      is_insufficient_balance: boolean
/** Failed Due to Invalid Payment */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout */
      is_pathfinding_timeout: boolean
/** Failed Due to Route Not Found */
      is_route_not_found: boolean
      route?: {
/** Route Total Fee Tokens Rounded Down */
        fee: number
/** Route Total Fee Millitokens */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Hop Forwarding Fee Rounded Down Tokens */
          fee: number
/** Hop Forwarding Fee Millitokens */
          fee_mtokens: string
/** Hop Forwarding Tokens Rounded Down */
          forward: number
/** Hop Forwarding Millitokens */
          forward_mtokens: string
/** Hop Sending To Public Key Hex */
          public_key: string
/** Hop CTLV Expiration Height */
          timeout: number
        }]
/** Payment Sending Millitokens */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Sending Tokens Rounded Up */
        safe_tokens: number
/** Payment CLTV Expiration Height */
        timeout: number
/** Payment Sending Tokens Rounded Down */
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
/** Pay Through Specific Final Hop Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens To Pay */
      max_fee?: number
/** Maximum Fee Millitokens to Pay */
      max_fee_mtokens?: string
/** Maximum Simultaneous Paths */
      max_paths?: number
/** Maximum Height of Payment Timeout */
      max_timeout_height?: number
      messages?: [{
/** Message Type number */
        type: string
/** Message Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Pay */
      mtokens?: string
/** Pay Out of Outgoing Channel Id */
      outgoing_channel?: string
/** Pay Out of Outgoing Channel Ids */
      outgoing_channels]: [string
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
/** BOLT 11 Payment Request */
      request: string
/** Tokens To Pay */
      tokens?: number
    }

    @throws
    <Error>

    @returns
/** Subscription EventEmitter */
    Object

    @event 'confirmed'
    {
/** Fee Tokens */
      fee: number
/** Total Fee Millitokens To Pay */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Channel Capacity Tokens */
        channel_capacity: number
/** Fee Millitokens */
        fee_mtokens: string
/** Forward Millitokens */
        forward_mtokens: string
/** Public Key Hex */
        public_key: string
/** Timeout Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Total Millitokens Paid */
      mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Preimage Hex */
      secret: string
/** Expiration Block Height */
      timeout: number
/** Total Tokens Paid */
      tokens: number
    }

    @event 'failed'
    {
/** Failed Due To Lack of Balance */
      is_insufficient_balance: boolean
/** Failed Due to Invalid Payment */
      is_invalid_payment: boolean
/** Failed Due to Pathfinding Timeout */
      is_pathfinding_timeout: boolean
/** Failed Due to Route Not Found */
      is_route_not_found: boolean
      route?: {
/** Route Total Fee Tokens Rounded Down */
        fee: number
/** Route Total Fee Millitokens */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Hop Forwarding Fee Rounded Down Tokens */
          fee: number
/** Hop Forwarding Fee Millitokens */
          fee_mtokens: string
/** Hop Forwarding Tokens Rounded Down */
          forward: number
/** Hop Forwarding Millitokens */
          forward_mtokens: string
/** Hop Sending To Public Key Hex */
          public_key: string
/** Hop CTLV Expiration Height */
          timeout: number
        }]
/** Payment Sending Millitokens */
        mtokens: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Sending Tokens Rounded Up */
        safe_tokens: number
/** Payment CLTV Expiration Height */
        timeout: number
/** Payment Sending Tokens Rounded Down */
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
/** Payment Hash Hex */
      id?: string
/** Authenticated */
      lnd: LND
/** Time to Spend Finding a Route Milliseconds */
      pathfinding_timeout?: number
      routes: [{
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
      }]
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'failure'
    {
      failure: [
/** Code */
        number
/** Failure Message */
        string
        {
/** Standard Format Channel Id */
          channel: string
/** Millitokens */
          mtokens?: string
          policy?: {
/** Base Fee Millitokens */
            base_fee_mtokens: string
/** Locktime Delta */
            cltv_delta: number
/** Fees Charged in Millitokens Per Million */
            fee_rate: number
/** Channel is Disabled */
            is_disabled?: boolean
/** Maximum HLTC Millitokens value */
            max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value */
            min_htlc_mtokens: string
          }
/** Public Key Hex */
          public_key: string
          update?: {
/** Chain Id Hex */
            chain: string
/** Channel Flags */
            channel_flags: number
/** Extra Opaque Data Hex */
            extra_opaque_data: string
/** Message Flags */
            message_flags: number
/** Channel Update Signature Hex */
            signature: string
          }
        }
      ]
    }

    @event 'paying'
    {
      route: {
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
      }
    }

    @event 'routing_failure'
    {
/** Standard Format Channel Id */
      channel?: string
/** Failure Hop Index */
      index?: number
/** Failure Related Millitokens */
      mtokens?: string
      policy?: {
/** Base Fee Millitokens */
        base_fee_mtokens: string
/** Locktime Delta */
        cltv_delta: number
/** Fees Charged in Millitokens Per Million */
        fee_rate: number
/** Channel is Disabled */
        is_disabled?: boolean
/** Maximum HLTC Millitokens value */
        max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value */
        min_htlc_mtokens: string
      }
/** Public Key Hex */
      public_key: string
/** Failure Reason */
      reason: string
      route: {
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
      }
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Failure Related CLTV Timeout Height */
      timeout_height?: number
      update?: {
/** Chain Id Hex */
        chain: string
/** Channel Flags */
        channel_flags: number
/** Extra Opaque Data Hex */
        extra_opaque_data: string
/** Message Flags */
        message_flags: number
/** Channel Update Signature Hex */
        signature: string
      }
    }

    @event 'success'
    {
/** Fee Paid Tokens */
      fee: number
/** Fee Paid Millitokens */
      fee_mtokens: string
      hops: [{
/** Standard Format Channel Id */
        channel: string
/** Hop Channel Capacity Tokens */
        channel_capacity: number
/** Hop Forward Fee Millitokens */
        fee_mtokens: string
/** Hop Forwarded Millitokens */
        forward_mtokens: string
/** Hop CLTV Expiry Block Height */
        timeout: number
      }]
/** Payment Hash Hex */
      id: string
/** Is Confirmed */
      is_confirmed: boolean
/** Is Outoing */
      is_outgoing: boolean
/** Total Millitokens Sent */
      mtokens: string
      route: {
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
      }
/** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number
/** Payment Tokens Rounded Up */
      safe_tokens: number
/** Payment Secret Preimage Hex */
      secret: string
/** Total Tokens Sent */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'connected'
    {
/** Connected Peer Public Key Hex */
      public_key: string
    }

    @event 'disconnected'
    {
/** Disconnected Peer Public Key Hex */
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
/** Final CLTV Delta */
      cltv_delta?: number
/** Destination Public Key Hex */
      destination: string
      features?: [{
/** Feature Bit */
        bit: number
      }]
      ignore?: [{
/** Public Key Hex */
        from_public_key: string
/** To Public Key Hex */
        to_public_key?: string
      }]
/** Incoming Peer Public Key Hex */
      incoming_peer?: string
/** Authenticated */
      lnd: LND
/** Maximum Fee Tokens */
      max_fee?: number
/** Maximum Fee Millitokens to Probe */
      max_fee_mtokens?: string
/** Maximum CLTV Timeout Height */
      max_timeout_height?: number
      messages?: [{
/** Message To Final Destination Type number */
        type: string
/** Message To Final Destination Raw Value Hex Encoded */
        value: string
      }]
/** Millitokens to Probe */
      mtokens?: string
/** Outgoing Channel Id */
      outgoing_channel?: string
/** Skip Individual Path Attempt After Milliseconds */
      path_timeout_ms?: number
/** Payment Identifier Hex */
      payment?: string
/** Fail Entire Probe After Milliseconds */
      probe_timeout_ms?: number
      routes?: [[{
/** Base Routing Fee In Millitokens */
        base_fee_mtokens?: number
/** Channel Capacity Tokens */
        channel_capacity?: number
/** Standard Format Channel Id */
        channel?: string
/** CLTV Blocks Delta */
        cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
        fee_rate?: number
/** Forward Edge Public Key Hex */
        public_key: string
      }]]
/** Tokens to Probe */
      tokens?: number
/** Total Millitokens Across Paths */
      total_mtokens?: string
    }

    @returns
/** Probe Subscription Event Emitter */
    Object

    @event 'error'
/** Failure Message */
    <Failure Code number>, string

    @event 'probe_success'
    {
      route: {
/** Route Confidence Score Out Of One Million */
        confidence?: number
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Payment Identifier Hex */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Sent Tokens Rounded Up */
        safe_tokens: number
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
/** Total Millitokens */
        total_mtokens?: string
      }
    }

    @event 'probing'
    {
      route: {
/** Route Confidence Score Out Of One Million */
        confidence?: number
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Payment Identifier Hex */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Sent Tokens Rounded Up */
        safe_tokens: number
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
/** Total Millitokens */
        total_mtokens?: string
      }
    }

    @event 'routing_failure'
    {
/** Standard Format Channel Id */
      channel?: string
/** Millitokens */
      mtokens?: string
      policy?: {
/** Base Fee Millitokens */
        base_fee_mtokens: string
/** Locktime Delta */
        cltv_delta: number
/** Fees Charged in Millitokens Per Million */
        fee_rate: number
/** Channel is Disabled */
        is_disabled?: boolean
/** Maximum HLTC Millitokens Value */
        max_htlc_mtokens: string
/** Minimum HTLC Millitokens Value */
        min_htlc_mtokens: string
      }
/** Public Key Hex */
      public_key: string
/** Failure Reason */
      reason: string
      route: {
/** Route Confidence Score Out Of One Million */
        confidence?: number
/** Total Fee Tokens To Pay */
        fee: number
/** Total Fee Millitokens To Pay */
        fee_mtokens: string
        hops: [{
/** Standard Format Channel Id */
          channel: string
/** Channel Capacity Tokens */
          channel_capacity: number
/** Fee */
          fee: number
/** Fee Millitokens */
          fee_mtokens: string
/** Forward Tokens */
          forward: number
/** Forward Millitokens */
          forward_mtokens: string
/** Public Key Hex */
          public_key: string
/** Timeout Block Height */
          timeout: number
        }]
        messages?: [{
/** Message Type number */
          type: string
/** Message Raw Value Hex Encoded */
          value: string
        }]
/** Total Millitokens To Pay */
        mtokens: string
/** Payment Identifier Hex */
        payment?: string
/** Payment Forwarding Fee Rounded Up Tokens */
        safe_fee: number
/** Payment Sent Tokens Rounded Up */
        safe_tokens: number
/** Expiration Block Height */
        timeout: number
/** Total Tokens To Pay */
        tokens: number
/** Total Millitokens */
        total_mtokens?: string
      }
      update?: {
/** Chain Id Hex */
        chain: string
/** Channel Flags */
        channel_flags: number
/** Extra Opaque Data Hex */
        extra_opaque_data: string
/** Message Flags */
        message_flags: number
/** Channel Update Signature Hex */
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
/** Authenticated */
      lnd: LND
    }

    @throws
    <Error>

    @returns
/** EventEmitter */
    Object

    @event 'chain_transaction'
    {
/** Block Hash */
      block_id?: string
/** Confirmation Count */
      confirmation_count?: number
/** Confirmation Block Height */
      confirmation_height?: number
/** Created ISO 8601 Date */
      created_at: string
/** Fees Paid Tokens */
      fee?: number
/** Transaction Id */
      id: string
/** Is Confirmed */
      is_confirmed: boolean
/** Transaction Outbound */
      is_outgoing: boolean
/** Address */
      output_addresses: string
/** Tokens Including Fee */
      tokens: number
/** Raw Transaction Hex */
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
/** Base64 or Hex Serialized LND TLS */
      cert?: Cert
      socket?: <Host:Port string>
    }

    @throws
    <Error>

    @returns
    {
      lnd: {
/** Unlocker LND GRPC Api */
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
/** Lock Id Hex */
      id: string
/** Authenticated */
      lnd: LND
/** Unspent Transaction Id Hex */
      transaction_id: string
/** Unspent Transaction Output Index */
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
/** Unauthenticated */
      lnd: LND
/** Wallet Password */
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
/** Transaction Label */
      description: string
/** Transaction Id Hex */
      id: string
/** Authenticated */
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
/** Add Socket */
      add_socket?: string
/** Authenticated */
      lnd: LND
/** Watchtower Public Key Hex */
      public_key: string
/** Remove Socket */
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
/** Base Fee Millitokens Charged */
      base_fee_mtokens?: number
/** Base Fee Tokens Charged */
      base_fee_tokens?: number
/** HTLC CLTV Delta */
      cltv_delta?: number
/** Fee Rate In Millitokens Per Million */
      fee_rate?: number
/** Authenticated */
      lnd: LND
/** Maximum HTLC Millitokens to Forward */
      max_htlc_mtokens?: string
/** Minimum HTLC Millitokens to Forward */
      min_htlc_mtokens?: string
/** Channel Funding Transaction Id */
      transaction_id?: string
/** Channel Funding Transaction Output Index */
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
/** Individual Channel Backup Hex */
      backup: string
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** LND Error */
      err?: Object
/** Backup is Valid */
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
/** Funding Transaction Id Hex */
        transaction_id: string
/** Funding Transaction Output Index */
        transaction_vout: number
      }]
/** Authenticated */
      lnd: LND
    }

    @returns via cbk or Promise
    {
/** Backup is Valid */
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
/** Authenticated */
      lnd: LND
/** Message Preimage Bytes Hex Encoded */
      preimage: string
/** Signature Valid For Public Key Hex */
      public_key: string
/** Signature Hex */
      signature: string
    }

    @returns via cbk or Promise
    {
/** Signature is Valid */
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
/** Authenticated */
      lnd: LND
/** Message */
      message: string
/** Signature Hex */
      signature: string
    }

    @returns via cbk or Promise
    {
/** Public Key Hex */
      signed_by: string
    }

Example:

```node
const {verifyMessage} = require('ln-service');
const message = 'foo';
const signature = 'badSignature';
const signedBy = (await verifyMessage({lnd, message, signature})).signed_by;
```

