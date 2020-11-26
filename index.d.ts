import * as stream from "stream";
/**
 * TODO:
 * - errors
 * - replace unknown result types
 * - tokens number postfix
 * - inline ChannelPolicy, Channel, Routes, Hop for safety
 * - remove obsolete LND objects
 * - fix capitalized methods
 * - fix potentially missing array
 * - check log function
 */

declare module "ln-service" {
  export type LND = {
    autopilot: any;
    chain: any;
    default: any;
    invoices: any;
    router: any;
    signer: any;
    tower_client: any;
    tower_server: any;
    wallet: any;
    version: any;
  };
  export type LightningNetworkDaemon = LND;

  export type LNService = {
    /**
     * Initiate a gRPC API Methods Object for authenticated methods
     *
     * Both the `cert` and `macaroon` expect the entire serialized LND generated file
     *
     * See: https://github.com/alexbosworth/ln-service#authenticatedLndGrpc
     */
    authenticatedLndGrpc: (variables: {
      cert?: string;
      macaroon: string;
      socket?: string;
    }) => { lnd: LND };
  };
  export type LightningNetworkService = LNService;

  export type Args<TArgs> = {
    /** LND API Object */
    lnd: LND;
  } & TArgs;

  export type LNDMethod<TArgs, TResult = void, TError = Error> = {
    (args: Args<TArgs>): Promise<TResult>;
    (
      args: Args<TArgs>,
      callback: (error: TError, result: TResult) => void
    ): void;
  };

  export type MethodWithoutLND<TArgs, TResult = void, TError = Error> = {
    (args: TArgs): Promise<TResult>;
    (args: TArgs, callback: (error: TError, result: TResult) => void): void;
  };

  const lnService: LNService;
  export default lnService;

  export type AddPeerArgs = Args<{
    /** Add Peer as Temporary Peer, default: `false` */
    is_temporary?: boolean;
    /** Public Key Hex */
    public_key: string;
    /** Retry Count */
    retry_count?: number;
    /** Delay Retry By Milliseconds */
    retry_delay?: number;
    /** Host Network Address And Optional Port, format: ip:port */
    socket: string;
    /** Connection Attempt Timeout Milliseconds */
    timeout?: number;
  }>;

  /**
   * Add a peer if possible (not self, or already connected)
   *
   * Requires `peers:write` permission
   *
   * `timeout` is not supported in LND 0.11.1 and below
   */
  export const addPeer: LNDMethod<AddPeerArgs>;

  export type BroadcastChainTransactionArgs = {
    /** Transaction Label */
    description?: string;
    /** Transaction Hex */
    transaction: string;
  };

  export type BroadcastChainTransactionResult = {
    id: string;
  };

  /**
   * Publish a raw blockchain transaction to Blockchain network peers
   *
   * Requires LND built with `walletrpc` tag
   */
  export const broadcastChainTransaction: LNDMethod<
    BroadcastChainTransactionArgs,
    BroadcastChainTransactionResult
  >;

  export type ChannelPolicy = {
    /** Base Fee Millitokens */
    base_fee_mtokens: string;
    /** CLTV Delta */
    cltv_delta: number;
    /** Fee Rate */
    fee_rate: number;
    /** Channel is Disabled */
    is_disabled: boolean;
    /** Maximum HTLC Millitokens */
    max_htlc_mtokens: string;
    /** Minimum HTLC Millitokens */
    min_htlc_mtokens: string;
    /** Public Key Hex */
    public_key: string;
  };

  export type Channel = {
    /** Capacity Tokens */
    capacity: number;
    /** Standard Channel Id */
    id: string;
    policies: ChannelPolicy[];
  };

  export type Hop = {
    /** Base Fee Millitokens */
    base_fee_mtokens: string;
    /** Standard Channel Id */
    channel: string;
    /** Channel Capacity Tokens */
    channel_capacity: number;
    /** CLTV Delta */
    cltv_delta: number;
    /** Fee Rate */
    fee_rate: number;
    /** Public Key Hex */
    public_key: string;
  };

  export type CalculateHopsArgs = {
    channels: Channel[];
    /** End Public Key Hex */
    end: string;
    ignore?: {
      /** Standard Format Channel Id */
      channel?: string;
      /** Public Key Hex */
      public_key: string;
    }[];
    /** Millitokens */
    mtokens: number;
    /** Start Public Key Hex */
    start: string;
  };

  export type CalculateHopsResult = {
    hops?: Hop[];
  };

  /**
   * Calculate hops between start and end nodes
   */
  export const calculateHops: LNDMethod<CalculateHopsArgs, CalculateHopsResult>;

  export type CalculatePathsArgs = {
    channels: Channel[];
    /** End Public Key Hex */
    end: string;
    /** Paths To Return Limit */
    limit?: number;
    /** Millitokens */
    mtokens: number;
    /** Start Public Key Hex */
    start: string;
  };

  export type CalculatePathsResult = { paths?: { hops: Hop[] }[] };

  /**
   * Calculate multiple routes to a destination
   */
  export const calculatePaths: LNDMethod<
    CalculatePathsArgs,
    CalculateHopsResult
  >;

  export type CancelHodlInvoiceArgs = {
    /** Payment Preimage Hash Hex */
    id: string;
  };

  /**
   * Cancel an invoice
   *
   * This call can cancel both HODL invoices and also void regular invoices
   *
   * Requires LND built with `invoicesrpc`
   *
   * Requires `invoices:write` permission
   */
  export const cancelHodlInvoice: LNDMethod<CancelHodlInvoiceArgs, unknown>;

  export type CancelPendingChannelArgs = {
    /** Pending Channel Id Hex */
    id: string;
  };

  /**
   * Cancel an external funding pending channel
   */
  export const cancelPendingChannel: LNDMethod<
    CancelPendingChannelArgs,
    unknown
  >;

  export type ChangePasswordArgs = {
    /** Current Password */
    current_password: string;
    /** New Password */
    new_password: string;
  };

  /**
   * Change wallet password
   *
   * Requires locked LND and unauthenticated LND connection
   */
  export const changePassword: LNDMethod<ChangePasswordArgs, unknown>;

  export type CloseChannelArgs = {
    /** Request Sending Local Channel Funds To Address */
    address?: string;
    /** Standard Format Channel Id */
    id?: string;
    /** Is Force Close */
    is_force_close?: boolean;
    /** Peer Public Key */
    public_key?: string;
    /** Peer Socket */
    socket?: string;
    /** Confirmation Target */
    target_confirmations?: number;
    /** Tokens Per Virtual Byte */
    tokens_per_vbyte?: number;
    /** Transaction Id Hex */
    transaction_id?: string;
    /** Transaction Output Index */
    transaction_vout?: number;
  };

  export type CloseChannelResult = {
    /** Closing Transaction Id Hex */
    transaction_id: string;
    /** Closing Transaction Vout */
    transaction_vout: number;
  };

  /**
   * Close a channel.
   *
   * Either an id or a transaction id / transaction output index is required
   *
   * If cooperatively closing, pass a public key and socket to connect
   *
   * Requires `info:read`, `offchain:write`, `onchain:write`, `peers:write` permissions
   */
  export const closeChannel: LNDMethod<CloseChannelArgs, CloseChannelResult>;

  export type ConnectWatchtowerArgs = {
    /** Watchtower Public Key Hex */
    public_key: string;
    /** Network Socket Address IP:PORT */
    socket: string;
  };

  /**
   * Connect to a watchtower
   *
   * This method requires LND built with `wtclientrpc` build tag
   *
   * Requires `offchain:write` permission
   */
  export const connectWatchtower: LNDMethod<ConnectWatchtowerArgs, unknown>;

  export type CreateChainAddressArgs = {
    /** Receive Address Type */
    format: "np2wpkh" | "p2wpkh";
    /** Get As-Yet Unused Address */
    is_unused?: boolean;
  };

  /**
   * Create a new receive address.
   *
   * Requires address:write permission
   */
  export const createChainAddress: LNDMethod<
    CreateChainAddressArgs,
    { address: unknown }
  >;

  export type CreateHodlInvoiceArgs = {
    /** Final CLTV Delta */
    cltv_delta?: number;
    /** Invoice Description */
    description?: string;
    /** Hashed Description of Payment Hex */
    description_hash?: string;
    /** Expires At ISO 8601 Date */
    expires_at?: string;
    /** Payment Hash Hex */
    id?: string;
    /** Is Fallback Address Included */
    is_fallback_included?: boolean;
    /** Is Fallback Address Nested */
    is_fallback_nested?: boolean;
    /** Invoice Includes Private Channels */
    is_including_private_channels?: boolean;
    /** Millitokens */
    mtokens?: string;
    /** Tokens */
    tokens?: number;
  };

  export type CreateHodlInvoiceResult = {
    /** Backup Address String */
    chain_address?: string;
    /** ISO 8601 Date String */
    created_at: string;
    /** Description String */
    description: string;
    /** Payment Hash Hex String */
    id: string;
    /** Millitokens Number */
    mtokens: number;
    /** BOLT 11 Encoded Payment Request String */
    request: string;
    /** Hex Encoded Payment Secret String */
    secret?: string;
    /** Tokens Number */
    tokens: number;
  };

  /**
   * Create HODL invoice. This invoice will not settle automatically when an HTLC arrives. It must be settled separately with the secret preimage.
   *
   * Warning: make sure to cancel the created invoice before its CLTV timeout.
   *
   * Requires LND built with `invoicesrpc` tag
   *
   * Requires `address:write`, `invoices:write` permission
   */
  export const createHodlInvoice: LNDMethod<
    CreateHodlInvoiceArgs,
    CreateHodlInvoiceResult
  >;

  export type CreateInvoiceArgs = {
    /** CLTV Delta */
    cltv_delta?: number;
    /** Invoice Description */
    description?: string;
    /** Hashed Description of Payment Hex */
    description_hash?: string;
    /** Expires At ISO 8601 Date */
    expires_at?: string;
    /** Is Fallback Address Included */
    is_fallback_included?: boolean;
    /** Is Fallback Address Nested */
    is_fallback_nested?: boolean;
    /** Invoice Includes Private Channels */
    is_including_private_channels?: boolean;
    /** Payment Preimage Hex */
    secret?: string;
    /** Millitokens */
    mtokens?: string;
    /** Tokens */
    tokens?: number;
  };

  export type CreateInvoiceResult = {
    /** Backup Address */
    chain_address?: string;
    /** ISO 8601 Date */
    created_at: string;
    /** Description */
    description?: string;
    /** Payment Hash Hex */
    id: string;
    /** Millitokens */
    mtokens?: string;
    /** BOLT 11 Encoded Payment Request */
    request: string;
    /** Hex Encoded Payment Secret */
    secret: string;
    /** Tokens */
    tokens?: number;
  };

  /**
   * Create a Lightning invoice.
   *
   * Requires `address:write`, `invoices:write` permissio
   */
  export const createInvoice: LNDMethod<CreateInvoiceArgs, CreateInvoiceResult>;

  export type CreateSeedArgs = {
    /** Seed Passphrase */
    passphrase?: string;
  };

  export type CreateSeedResult = {
    /** Cipher Seed Mnemonic */
    seed: string;
  };

  /**
   * Create a wallet seed
   *
   * Requires unlocked lnd and unauthenticated LND
   */
  export const createSeed: LNDMethod<CreateSeedArgs, CreateSeedResult>;

  export type CreateSignedRequestArgs = {
    /** Destination Public Key Hex */
    destination: string;
    /** Request Human Readable Part */
    hrp: string;
    /** Request Hash Signature Hex */
    signature: string;
    /** Request Tag Words */
    tags: number[];
  };

  export type CreateSignedResult = {
    /** BOLT 11 Encoded Payment Request */
    request: string;
  };

  /**
   * Assemble a signed payment request
   */
  export const createSignedRequest: MethodWithoutLND<
    CreateSignedRequestArgs,
    CreateSignedResult
  >;

  export type Route = {
    /** Base Fee Millitokens */
    base_fee_mtokens?: string;
    /** Standard Format Channel Id */
    channel?: string;
    /** Final CLTV Expiration Blocks Delta */
    cltv_delta?: number;
    /** Fees Charged in Millitokens Per Million */
    fee_rate?: number;
    /** Forward Edge Public Key Hex */
    public_key: string;
  };

  export type CreateUnsignedRequestArgs = {
    /** Chain Addresses */
    chain_addresses?: string[];
    /** CLTV Delta */
    cltv_delta?: number;
    /** Invoice Creation Date ISO 8601 */
    created_at?: string;
    /** Description */
    description?: string;
    /** Description Hash Hex */
    description_hash?: string;
    /** Public Key */
    destination: string;
    /** ISO 8601 Date */
    expires_at?: string;
    features: {
      /** BOLT 09 Feature Bit */
      bit: number;
    }[];
    /** Preimage SHA256 Hash Hex */
    id: string;
    /** Requested Milli-Tokens Value (can exceed number limit) */
    mtokens?: string;
    /** Network Name */
    network: string;
    /** Payment Identifier Hex */
    payment?: string;
    routes?: Route[][];
    /** Requested Chain Tokens Number (note: can differ from mtokens) */
    tokens?: number;
  };

  export type CreateUnsignedRequestResult = {
    /** Payment Request Signature Hash Hex */
    hash: string;
    /** Human Readable Part of Payment Request */
    hrp: string;
    /** Signature Hash Preimage Hex */
    preimage: string;
    /** Data Tag Numbers */
    tags: number[];
  };

  /**
   * Create an unsigned payment request
   */
  export const createUnsignedRequest: MethodWithoutLND<
    CreateUnsignedRequestArgs,
    CreateUnsignedRequestResult
  >;

  export type CreateWalletArgs = {
    /** AEZSeed Encryption Passphrase */
    passphrase?: string;
    /** Wallet Password */
    password: string;
    /** Seed Mnemonic */
    seed: string;
  };

  /**
   * Create a wallet
   *
   * Requires unlocked lnd and unauthenticated LND
   */
  export const createWallet: LNDMethod<CreateWalletArgs, unknown>;

  export type DecodePaymentRequestArgs = {
    /** BOLT 11 Payment Request */
    request: string;
  };

  export type DecodePaymentRequestResult = {
    /** Fallback Chain Address */
    chain_address: string;
    /** Final CLTV Delta */
    cltv_delta?: number;
    /** Payment Description */
    description: string;
    /** Payment Longer Description Hash */
    description_hash: string;
    /** Public Key */
    destination: string;
    /** ISO 8601 Date */
    expires_at: string;
    features: {
      /** BOLT 09 Feature Bit */
      bit: number;
      /** Feature is Known */
      is_known: boolean;
      /** Feature Support is Required To Pay */
      is_required: boolean;
      /** Feature Type */
      type: string;
    }[];
    /** Payment Hash */
    id: string;
    /** Requested Millitokens */
    mtokens: string;
    /** Payment Identifier Hex Encoded */
    payment?: string;
    routes: Route[][];
    /** Requested Tokens Rounded Up */
    safe_tokens: number;
    /** Requested Tokens Rounded Down */
    tokens: number;
  };

  /**
   * Get decoded payment request
   *
   * Requires `offchain:read` permission
   */
  export const decodePaymentRequest: LNDMethod<
    DecodePaymentRequestArgs,
    DecodePaymentRequestResult
  >;

  /**
   * Delete all forwarding reputations
   *
   * Requires `offchain:write` permissio
   */
  export const deleteForwardingReputations: LNDMethod<{}, unknown>;

  /**
   * Delete all records of payments
   *
   * Requires `offchain:write` permission
   */
  export const deletePayments: LNDMethod<{}, unknown>;

  export type DiffieHellmanComputeSecretArgs = {
    /** Key Family */
    key_family?: number;
    /** Key Index */
    key_index?: number;
    /** Public Key Hex */
    partner_public_key: string;
  };

  export type DiffieHellmanComputeSecretResult = {
    /** Shared Secret Hex */
    secret: string;
  };

  /**
   * Derive a shared secret
   *
   * Key family and key index default to 6 and 0, which is the node identity key
   *
   * Requires LND built with `signerrpc` build tag
   *
   * Requires `signer:generate` permission
   */
  export const diffieHellmanComputeSecret: LNDMethod<
    DiffieHellmanComputeSecretArgs,
    DiffieHellmanComputeSecretResult
  >;

  export type DisconnectWatchtowerArgs = {
    /** Watchtower Public Key Hex */
    public_key: string;
  };

  /**
   * Disconnect a watchtower
   *
   * Requires LND built with `wtclientrpc` build tag
   *
   * Requires `offchain:write` permission
   */
  export const disconnectWatchtower: LNDMethod<
    DisconnectWatchtowerArgs,
    unknown
  >;

  export type FundPendingChannelsArgs = {
    /** Pending Channel Id Hex */
    channels: string;
    /** Signed Funding Transaction PSBT Hex */
    funding: string;
  };

  /**
   * Fund pending channels
   *
   * Requires `offchain:write`, `onchain:write` permission
   */
  export const fundPendingChannels: LNDMethod<FundPendingChannelsArgs, unknown>;

  export type FundPSBTArgs = {
    /** Chain Fee Tokens Per Virtual Byte */
    fee_tokens_per_vbyte?: number;
    inputs?: {
      /** Unspent Transaction Id Hex */
      transaction_id: string;
      /** Unspent Transaction Output Index */
      transaction_vout: number;
    }[];
    outputs?: {
      /** Chain Address */
      address: string;
      /** Send Tokens Tokens */
      tokens: number;
    }[];
    /** Confirmations To Wait */
    target_confirmations?: number;
    /** Existing PSBT Hex */
    psbt?: string;
  };

  export type FundPSBTResult = {
    inputs: {
      /** UTXO Lock Expires At ISO 8601 Date */
      lock_expires_at?: string;
      /** UTXO Lock Id Hex */
      lock_id?: string;
      /** Unspent Transaction Id Hex */
      transaction_id: string;
      /** Unspent Transaction Output Index */
      transaction_vout: number;
    }[];
    outputs: {
      /** Spends To a Generated Change Output */
      is_change: boolean;
      /** Output Script Hex */
      output_script: string;
      /** Send Tokens Tokens */
      tokens: number;
    }[];
    /** Unsigned PSBT Hex */
    psbt: string;
  };

  /**
   * Lock and optionally select inputs to a partially signed transaction
   *
   * Specify outputs or PSBT with the outputs encoded
   *
   * If there are no inputs passed, internal UTXOs will be selected and locked
   *
   * Requires `onchain:write` permission
   *
   * Requires LND built with `walletrpc` tag
   *
   * This method is not supported in LND 0.11.1 and belo
   */
  export const fundPsbt: LNDMethod<FundPSBTArgs, FundPSBTResult>;

  export type GetAccessIdsResult = {
    ids: number[];
  };

  /**
   * Get outstanding access ids given out
   *
   * Note: this method is not supported in LND versions 0.11.1 and below
   *
   * Requires `macaroon:read` permission
   */
  export const getAccessIds: LNDMethod<{}, GetAccessIdsResult>;

  export type GetAutopilotArgs = {
    /** Get Score For Public Key Hex */
    node_scores?: [string];
  };

  export type GetAutopilotResult = {
    /** Autopilot is Enabled */
    is_enabled: boolean;
    nodes: {
      /** Local-adjusted Pref Attachment Score */
      local_preferential_score: number;
      /** Local-adjusted Externally Set Score */
      local_score: number;
      /** Preferential Attachment Score */
      preferential_score: number;
      /** Node Public Key Hex */
      public_key: string;
      /** Externally Set Score */
      score: number;
      /** Combined Weighted Locally-Adjusted Score */
      weighted_local_score: number;
      /** Combined Weighted Score */
      weighted_score: number;
    }[];
  };

  /**
	 * Get Autopilot status
	 * 
	 * Optionally, get the score of nodes as considered by the autopilot.
Local scores reflect an internal scoring that includes local channel info
	 * 
	 * Permission `info:read` is required
	 */
  export const getAutopilot: LNDMethod<GetAutopilotArgs, GetAutopilotResult>;

  export type GetBackupArgs = {
    /** Funding Transaction Id Hex */
    transaction_id: string;
    /** Funding Transaction Output Index */
    transaction_vout: number;
  };

  export type GetBackupResult = {
    /** Channel Backup Hex */
    backup: string;
  };

  /**
   * Get the static channel backup for a channel
   *
   * Requires `offchain:read` permission
   */
  export const getBackup: LNDMethod<GetBackupArgs, GetBackupResult>;

  export type GetBackupsResult = {
    /** All Channels Backup Hex */
    backup: string;
    channels: {
      /** Individualized Channel Backup Hex */
      backup: string;
      /** Channel Funding Transaction Id Hex */
      transaction_id: string;
      /** Channel Funding Transaction Output Index */
      transaction_vout: number;
    };
  };

  /**
   * Get all channel backups
   *
   * Requires `offchain:read` permission
   */
  export const getBackups: LNDMethod<{}, GetBackupsResult>;

  export type GetChainBalanceResult = {
    /** Confirmed Chain Balance Tokens */
    chain_balance: number;
  };

  /**
   * Get balance on the chain.
   *
   * Requires `onchain:read` permission
   */
  export const getChainBalance: LNDMethod<{}, GetChainBalanceResult>;

  export type GetChainFeeEstimateArgs = {
    send_to: {
      /** Address */
      address: string;
      /** Tokens */
      tokens: number;
    }[];
    /** Target Confirmations */
    target_confirmations?: number;
  };

  export type GetChainFeeEstimateResult = {
    /** Total Fee Tokens */
    fee: number;
    /** Fee Tokens Per VByte */
    tokens_per_vbyte: number;
  };

  /**
   * Get a chain fee estimate for a prospective chain send
   *
   * Requires `onchain:read` permission
   */
  export const getChainFeeEstimate: LNDMethod<
    GetChainFeeEstimateArgs,
    GetChainFeeEstimateResult
  >;

  export type GetChainFeeRateArgs = {
    /** Future Blocks Confirmation */
    confirmation_target?: number;
  };

  export type GetChainFeeRateResult = {
    /** Tokens Per Virtual Byte */
    tokens_per_vbyte: number;
  };

  /**
   * Get chain fee rate estimate
   *
   * Requires LND built with `walletrpc` tag
   *
   * Requires `onchain:read` permission
   */
  export const getChainFeeRate: LNDMethod<
    GetChainFeeRateArgs,
    GetChainFeeRateResult
  >;

  export type GetChainTransactionsArgs = {
    /** Confirmed After Current Best Chain Block Height */
    after?: number;
    /** Confirmed Before Current Best Chain Block Height */
    before?: number;
  };

  export type GetChainTransactionsResult = {
    transactions: {
      /** Block Hash */
      block_id?: string;
      /** Confirmation Count */
      confirmation_count?: number;
      /** Confirmation Block Height */
      confirmation_height?: number;
      /** Created ISO 8601 Date */
      created_at: string;
      /** Transaction Label */
      description?: string;
      /** Fees Paid Tokens */
      fee?: number;
      /** Transaction Id */
      id: string;
      /** Is Confirmed */
      is_confirmed: boolean;
      /** Transaction Outbound */
      is_outgoing: boolean;
      /** Address */
      output_addresses: string;
      /** Tokens Including Fee */
      tokens: number;
      /** Raw Transaction Hex */
      transaction?: string;
    }[];
  };

  /**
   * Get chain transactions.
   *
   * Requires `onchain:read` permission
   */
  export const getChainTransactions: LNDMethod<
    GetChainTransactionsArgs,
    GetChainTransactionsResult
  >;

  export type GetChannelBalanceArgs = {};

  export type GetChannelBalanceResult = {
    /** Channels Balance Tokens */
    channel_balance: number;
    /** Channels Balance Millitokens */
    channel_balance_mtokens?: string;
    /** Inbound Liquidity Tokens */
    inbound?: number;
    /** Inbound Liquidity Millitokens */
    inbound_mtokens?: string;
    /** Pending On-Chain Channels Balance Tokens */
    pending_balance: number;
    /** Pending On-Chain Inbound Liquidity Tokens */
    pending_inbound?: number;
    /** In-Flight Tokens */
    unsettled_balance?: number;
    /** In-Flight Millitokens */
    unsettled_balance_mtokens?: number;
  };

  /**
   * Get balance across channels.
   *
   * Requires `offchain:read` permission
   *
   * `channel_balance_mtokens` is not supported on LND 0.11.1 and below
   *
   * `inbound` and `inbound_mtokens` are not supported on LND 0.11.1 and below
   *
   * `pending_inbound` is not supported on LND 0.11.1 and below
   *
   * `unsettled_balance` is not supported on LND 0.11.1 and below
   *
   * `unsettled_balance_mtokens` is not supported on LND 0.11.1 and below
   */
  export const getChannelBalance: LNDMethod<
    GetChannelBalanceArgs,
    GetChannelBalanceResult
  >;

  export type GetChannelArgs = {
    /** Standard Format Channel Id */
    id: string;
  };

  export type GetChannelResult = {
    /** Maximum Tokens */
    capacity: number;
    /** Standard Format Channel Id */
    id: string;
    policies: {
      /** Base Fee Millitokens */
      base_fee_mtokens?: string;
      /** Locktime Delta */
      cltv_delta?: number;
      /** Fees Charged Per Million Millitokens */
      fee_rate?: number;
      /** Channel Is Disabled */
      is_disabled?: boolean;
      /** Maximum HTLC Millitokens Value */
      max_htlc_mtokens?: string;
      /** Minimum HTLC Millitokens Value */
      min_htlc_mtokens?: string;
      /** Node Public Key */
      public_key: string;
      /** Policy Last Updated At ISO 8601 Date */
      updated_at?: string;
    }[];
    /** Transaction Id Hex */
    transaction_id: string;
    /** Transaction Output Index */
    transaction_vout: number;
    /** Last Update Epoch ISO 8601 Date */
    updated_at?: string;
  };

  /**
   * Get graph information about a channel on the network
   *
   * Requires `info:read` permission
   */
  export const getChannel: LNDMethod<GetChannelArgs, GetChannelResult>;

  export type GetChannelsArgs = {
    /** Limit Results To Only Active Channels */
    is_active?: boolean;
    /** Limit Results To Only Offline Channels */
    is_offline?: boolean;
    /** Limit Results To Only Private Channels */
    is_private?: boolean;
    /** Limit Results To Only Public Channels */
    is_public?: boolean;
    /** Only Channels With Public Key Hex */
    partner_public_key?: string;
  };

  export type GetChannelsResult = {
    channels: {
      /** Channel Token Capacity */
      capacity: number;
      /** Commit Transaction Fee */
      commit_transaction_fee: number;
      /** Commit Transaction Weight */
      commit_transaction_weight: number;
      /** Coop Close Restricted to Address */
      cooperative_close_address?: string;
      /** Prevent Coop Close Until Height */
      cooperative_close_delay_height?: number;
      /** Standard Format Channel Id */
      id: string;
      /** Channel Active */
      is_active: boolean;
      /** Channel Is Closing */
      is_closing: boolean;
      /** Channel Is Opening */
      is_opening: boolean;
      /** Channel Partner Opened Channel */
      is_partner_initiated: boolean;
      /** Channel Is Private */
      is_private: boolean;
      /** Remote Key Is Static */
      is_static_remote_key: boolean;
      /** Local Balance Tokens */
      local_balance: number;
      /** Local CSV Blocks Delay */
      local_csv?: number;
      /** Remote Non-Enforceable Amount Tokens */
      local_dust?: number;
      /** Local Initially Pushed Tokens */
      local_given?: number;
      /** Local Maximum Attached HTLCs */
      local_max_htlcs?: number;
      /** Local Maximum Pending Millitokens */
      local_max_pending_mtokens?: string;
      /** Local Minimum HTLC Millitokens */
      local_min_htlc_mtokens?: string;
      /** Local Reserved Tokens */
      local_reserve: number;
      /** Channel Partner Public Key */
      partner_public_key: string;
      pending_payments: {
        /** Payment Preimage Hash Hex */
        id: string;
        /** Forward Inbound From Channel Id */
        in_channel?: string;
        /** Payment Index on Inbound Channel */
        in_payment?: number;
        /** Payment is a Forward */
        is_forward?: boolean;
        /** Payment Is Outgoing */
        is_outgoing: boolean;
        /** Forward Outbound To Channel Id */
        out_channel?: string;
        /** Payment Index on Outbound Channel */
        out_payment?: number;
        /** Payment Attempt Id */
        payment?: number;
        /** Chain Height Expiration */
        timeout: number;
        /** Payment Tokens */
        tokens: number;
      }[];
      /** Received Tokens */
      received: number;
      /** Remote Balance Tokens */
      remote_balance: number;
      /** Remote CSV Blocks Delay */
      remote_csv?: number;
      /** Remote Non-Enforceable Amount Tokens */
      remote_dust?: number;
      /** Remote Initially Pushed Tokens */
      remote_given?: number;
      /** Remote Maximum Attached HTLCs */
      remote_max_htlcs?: number;
      /** Remote Maximum Pending Millitokens */
      remote_max_pending_mtokens?: string;
      /** Remote Minimum HTLC Millitokens */
      remote_min_htlc_mtokens?: string;
      /** Remote Reserved Tokens */
      remote_reserve: number;
      /** Sent Tokens */
      sent: number;
      /** Monitoring Uptime Channel Down Milliseconds */
      time_offline?: number;
      /** Monitoring Uptime Channel Up Milliseconds */
      time_online?: number;
      /** Blockchain Transaction Id */
      transaction_id: string;
      /** Blockchain Transaction Vout */
      transaction_vout: number;
      /** Unsettled Balance Tokens */
      unsettled_balance: number;
    }[];
  };

  /**
	 * Get channels
	 * 
	 * Requires `offchain:read` permission
	 * 
	 * `in_channel`, `in_payment`, `is_forward`, `out_channel`, `out_payment`,
`payment` are not supported on LND 0.11.1 and belo
	 */
  export const getChannels: LNDMethod<GetChannelsArgs, GetChannelsResult>;

  export type GetClosedChannelsArgs = {
    /** Only Return Breach Close Channels */
    is_breach_close?: boolean;
    /** Only Return Cooperative Close Channels */
    is_cooperative_close?: boolean;
    /** Only Return Funding Canceled Channels */
    is_funding_cancel?: boolean;
    /** Only Return Local Force Close Channels */
    is_local_force_close?: boolean;
    /** Only Return Remote Force Close Channels */
    is_remote_force_close?: boolea;
  };

  export type GetClosedChannelsResult = {
    channels: {
      /** Closed Channel Capacity Tokens */
      capacity: number;
      /** Channel Balance Output Spent By Tx Id */
      close_balance_spent_by?: string;
      /** Channel Balance Close Tx Output Index */
      close_balance_vout?: number;
      close_payments: {
        /** Payment Is Outgoing */
        is_outgoing: boolean;
        /** Payment Is Claimed With Preimage */
        is_paid: boolean;
        /** Payment Resolution Is Pending */
        is_pending: boolean;
        /** Payment Timed Out And Went Back To Payer */
        is_refunded: boolean;
        /** Close Transaction Spent By Transaction Id Hex */
        spent_by?: string;
        /** Associated Tokens */
        tokens: number;
        /** Transaction Id Hex */
        transaction_id: string;
        /** Transaction Output Index */
        transaction_vout: number;
      }[];
      /** Channel Close Confirmation Height */
      close_confirm_height?: number;
      /** Closing Transaction Id Hex */
      close_transaction_id?: string;
      /** Channel Close Final Local Balance Tokens */
      final_local_balance: number;
      /** Closed Channel Timelocked Tokens */
      final_time_locked_balance: number;
      /** Closed Standard Format Channel Id */
      id?: string;
      /** Is Breach Close */
      is_breach_close: boolean;
      /** Is Cooperative Close */
      is_cooperative_close: boolean;
      /** Is Funding Cancelled Close */
      is_funding_cancel: boolean;
      /** Is Local Force Close */
      is_local_force_close: boolean;
      /** Channel Was Closed By Channel Peer */
      is_partner_closed?: boolean;
      /** Channel Was Initiated By Channel Peer */
      is_partner_initiated?: boolean;
      /** Is Remote Force Close */
      is_remote_force_close: boolean;
      /** Partner Public Key Hex */
      partner_public_key: string;
      /** Channel Funding Transaction Id Hex */
      transaction_id: string;
      /** Channel Funding Output Index */
      transaction_vout: number;
    }[];
  };

  /**
   * Get closed out channels
   *
   * Multiple close type flags are supported.
   *
   * Requires `offchain:read` permission
   */
  export const getClosedChannels: LNDMethod<
    GetClosedChannelsArgs,
    GetClosedChannelsResult
  >;

  export type GetConnectedWatchTowersArgs = {};

  export type GetConnectedWatchTowersResult = {
    /** Maximum Updates Per Session */
    max_session_update_count: number;
    /** Sweep Tokens per Virtual Byte */
    sweep_tokens_per_vbyte: number;
    /** Total Backups Made Count */
    backups_count: number;
    /** Total Backup Failures Count */
    failed_backups_count: number;
    /** Finished Updated Sessions Count */
    finished_sessions_count: number;
    /** As Yet Unacknowledged Backup Requests Count */
    pending_backups_count: number;
    /** Total Backup Sessions Starts Count */
    sessions_count: number;
    towers: {
      /** Tower Can Be Used For New Sessions */
      is_active: boolean;
      /** Identity Public Key Hex */
      public_key: string;
      sessions: {
        /** Total Successful Backups Made Count */
        backups_count: number;
        /** Backups Limit */
        max_backups_count: number;
        /** Backups Pending Acknowledgement Count */
        pending_backups_count: number;
        /** Fee Rate in Tokens Per Virtual Byte */
        sweep_tokens_per_vbyte: number;
      }[];
      /** Tower Network Addresses (IP:Port) */
      sockets: string[];
    }[];
  };

  /**
   * Get a list of connected watchtowers and watchtower info
   * Requires LND built with `wtclientrpc` build tag
   * Requires `offchain:read` permission
   * Includes previously connected watchtowers
   */
  export const getConnectedWatchTowers: LNDMethod<
    GetConnectedWatchTowersArgs,
    GetConnectedWatchTowersResult
  >;

  export type GetFeeRatesArgs = {};

  export type GetFeeRatesResult = {
    channels: {
      /** Base Flat Fee Tokens Rounded Up */
      base_fee: number;
      /** Base Flat Fee Millitokens */
      base_fee_mtokens: string;
      /** Standard Format Channel Id */
      id: string;
      /** Channel Funding Transaction Id Hex */
      transaction_id: string;
      /** Funding Outpoint Output Index */
      transaction_vout: number;
    }[];
  };

  /**
   * Get a rundown on fees for channels
   *
   * Requires `offchain:read` permission
   */
  export const getFeeRates: LNDMethod<GetFeeRatesArgs, GetFeeRatesResult>;

  export type GetForwardingConfidenceArgs = {
    /** From Public Key Hex */
    from: string;
    /** Millitokens To Send */
    mtokens: string;
    /** To Public Key Hex */
    to: string;
  };

  export type GetForwardingConfidenceResult = {
    /** Success Confidence Score Out Of One Million */
    confidence: number;
  };

  /**
   * Get the confidence in being able to send between a direct pair of nodes
   */
  export const getForwardingConfidence: LNDMethod<
    GetForwardingConfidenceArgs,
    GetForwardingConfidenceResult
  >;

  export type GetForwardingReputationsArgs = {};

  export type GetForwardingReputationsResult = {
    nodes: {
      peers: {
        /** Failed to Forward Tokens */
        failed_tokens?: number;
        /** Forwarded Tokens */
        forwarded_tokens?: number;
        /** Failed Forward At ISO-8601 Date */
        last_failed_forward_at?: string;
        /** Forwarded At ISO 8601 Date */
        last_forward_at?: string;
        /** To Public Key Hex */
        to_public_key: string;
      }[];
      /** Node Identity Public Key Hex */
      public_key: string;
    }[];
  };

  /**
   * Get the set of forwarding reputations
   *
   * Requires `offchain:read` permissio
   */
  export const getForwardingReputations: LNDMethod<
    GetForwardingReputationsArgs,
    GetForwardingReputationsResult
  >;

  export type GetForwardsArgs = {
    /** Get Only Payments Forwarded At Or After ISO 8601 Date */
    after?: string;
    /** Get Only Payments Forwarded Before ISO 8601 Date */
    before?: string;
    /** Page Result Limit */
    limit?: number;
    /** Opaque Paging Token */
    token?: string;
  };

  export type GetForwardsResult = {
    forwards: {
      /** Forward Record Created At ISO 8601 Date */
      created_at: string;
      /** Fee Tokens Charged */
      fee: number;
      /** Approximated Fee Millitokens Charged */
      fee_mtokens: string;
      /** Incoming Standard Format Channel Id */
      incoming_channel: string;
      /** Forwarded Millitokens */
      mtokens: string;
      /** Outgoing Standard Format Channel Id */
      outgoing_channel: string;
      /** Forwarded Tokens */
      tokens: number;
    }[];
    /** Continue With Opaque Paging Token */
    next?: string;
  };

  /**
   * Get forwarded payments, from oldest to newest
   *
   * When using an `after` date a `before` date is required.
   *
   * If a next token is returned, pass it to get additional page of results.
   *
   * Requires `offchain:read` permission
   */
  export const getForwards: LNDMethod<GetForwardsArgs, GetForwardsResult>;

  export type GetHeightArgs = {};

  export type GetHeightResult = {
    /** Best Chain Hash Hex */
    current_block_hash: string;
    /** Best Chain Height */
    current_block_height: number;
  };

  /**
   * Lookup the current best block height
   * LND with `chainrpc` build tag and `onchain:read` permission is suggested
   * Otherwise, `info:read` permission is require
   */
  export const getHeight: LNDMethod<GetHeightArgs, GetHeightResult>;

  export type GetIdentityArgs = {};

  export type GetIdentityResult = {
    /** Node Identity Public Key Hex */
    public_key: string;
  };

  /**
   * Lookup the identity key for a node
   *
   * LND with `walletrpc` build tag and `address:read` permission is suggested
   *
   * Otherwise, `info:read` permission is require
   */
  export const getIdentity: LNDMethod<GetIdentityArgs, GetIdentityResult>;

  export type GetInvoiceArgs = {
    /** Payment Hash Id Hex */
    id: string;
  };

  export type GetInvoiceResult = {
    /** Fallback Chain Address */
    chain_address?: string;
    /** CLTV Delta */
    cltv_delta: number;
    /** Settled at ISO 8601 Date */
    confirmed_at?: string;
    /** ISO 8601 Date */
    created_at: string;
    /** Description */
    description: string;
    /** Description Hash Hex */
    description_hash?: string;
    /** ISO 8601 Date */
    expires_at: string;
    features: {
      /** BOLT 09 Feature Bit */
      bit: number;
      /** Feature is Known */
      is_known: boolean;
      /** Feature Support is Required To Pay */
      is_required: boolean;
      /** Feature Type */
      type: string;
    }[];
    /** Payment Hash */
    id: string;
    /** Invoice is Canceled */
    is_canceled?: boolean;
    /** Invoice is Confirmed */
    is_confirmed: boolean;
    /** HTLC is Held */
    is_held?: boolean;
    /** Invoice is Private */
    is_private: boolean;
    /** Invoice is Push Payment */
    is_push?: boolean;
    payments: {
      /** Payment Settled At ISO 8601 Date */
      confirmed_at?: string;
      /** Payment Held Since ISO 860 Date */
      created_at: string;
      /** Payment Held Since Block Height */
      created_height: number;
      /** Incoming Payment Through Channel Id */
      in_channel: string;
      /** Payment is Canceled */
      is_canceled: boolean;
      /** Payment is Confirmed */
      is_confirmed: boolean;
      /** Payment is Held */
      is_held: boolean;
      messages: {
        /** Message Type number */
        type: string;
        /** Raw Value Hex */
        value: string;
      }[];
      /** Incoming Payment Millitokens */
      mtokens: string;
      /** Pending Payment Channel HTLC Index */
      pending_index?: number;
      /** Payment Tokens */
      tokens: number;
    }[];
    /** Received Tokens */
    received: number;
    /** Received Millitokens */
    received_mtokens: string;
    /** Bolt 11 Invoice */
    request?: string;
    /** Secret Preimage Hex */
    secret: string;
    /** Tokens */
    tokens: number;
  };

  /**
	 * Lookup a channel invoice.
	 * 
	 * The received value and the invoiced value may differ as invoices may be
over-paid.
	 *
	 * Requires `invoices:read` permission
	 */
  export const getInvoice: LNDMethod<GetInvoiceArgs, GetInvoiceResult>;

  export type GetInvoicesArgs = {
    /** Page Result Limit */
    limit?: number;
    /** Opaque Paging Token */
    token?: string;
  };

  export type GetInvoicesResult = {
    invoices: {
      /** Fallback Chain Address */
      chain_address?: string;
      /** Settled at ISO 8601 Date */
      confirmed_at?: string;
      /** ISO 8601 Date */
      created_at: string;
      /** Description */
      description: string;
      /** Description Hash Hex */
      description_hash?: string;
      /** ISO 8601 Date */
      expires_at: string;
      features: {
        /** BOLT 09 Feature Bit */
        bit: number;
        /** Feature is Known */
        is_known: boolean;
        /** Feature Support is Required To Pay */
        is_required: boolean;
        /** Feature Type */
        type: string;
      }[];
      /** Payment Hash */
      id: string;
      /** Invoice is Canceled */
      is_canceled?: boolean;
      /** Invoice is Confirmed */
      is_confirmed: boolean;
      /** HTLC is Held */
      is_held?: boolean;
      /** Invoice is Private */
      is_private: boolean;
      /** Invoice is Push Payment */
      is_push?: boolean;
      payments: {
        /** Payment Settled At ISO 8601 Date */
        confirmed_at?: string;
        /** Payment Held Since ISO 860 Date */
        created_at: string;
        /** Payment Held Since Block Height */
        created_height: number;
        /** Incoming Payment Through Channel Id */
        in_channel: string;
        /** Payment is Canceled */
        is_canceled: boolean;
        /** Payment is Confirmed */
        is_confirmed: boolean;
        /** Payment is Held */
        is_held: boolean;
        messages: {
          /** Message Type number */
          type: string;
          /** Raw Value Hex */
          value: string;
        }[];
        /** Incoming Payment Millitokens */
        mtokens: string;
        /** Pending Payment Channel HTLC Index */
        pending_index?: number;
        /** Payment Tokens */
        tokens: number;
        /** Total Millitokens */
        total_mtokens?: string;
      }[];
      /** Received Tokens */
      received: number;
      /** Received Millitokens */
      received_mtokens: string;
      /** Bolt 11 Invoice */
      request?: string;
      /** Secret Preimage Hex */
      secret: string;
      /** Tokens */
      tokens: number;
    }[];
    /** Next Opaque Paging Token */
    next?: string;
  };

  /**
   * Get all created invoices.
   *
   * If a next token is returned, pass it to get another page of invoices.
   *
   * Requires `invoices:read` permission
   */
  export const getInvoices: LNDMethod<GetInvoicesArgs, GetInvoicesResult>;

  export type GetMethodsArgs = {};

  export type GetMethodsResult = {
    methods: {
      /** Method Endpoint Path */
      endpoint: string;
      /** Entity:Action */
      permissions: string[];
    }[];
  };

  /**
   * Get the list of all methods and their associated requisite permissions
   *
   * Note: this method is not supported in LND versions 0.11.1 and below
   *
   * Requires `info:read` permissio
   */
  export const getMethods: LNDMethod<GetMethodsArgs, GetMethodsResult>;

  export type GetNetworkCentralityArgs = {};

  export type GetNetworkCentralityResult = {
    nodes: {
      /** Betweenness Centrality */
      betweenness: number;
      /** Normalized Betweenness Centrality */
      betweenness_normalized: number;
      /** Node Public Key Hex */
      public_key: string;
    }[];
  };

  /**
   * Get the graph centrality scores of the nodes on the network
   * Scores are from 0 to 1,000,000.
   * Requires `info:read` permissio
   */
  export const getNetworkCentrality: LNDMethod<
    GetNetworkCentralityArgs,
    GetNetworkCentralityResult
  >;

  export type GetNetworkGraphArgs = {};

  export type GetNetworkGraphResult = {
    channels: {
      /** Channel Capacity Tokens */
      capacity: number;
      /** Standard Format Channel Id */
      id: string;
      policies: {
        /** Bae Fee Millitokens */
        base_fee_mtokens?: string;
        /** CLTV Height Delta */
        cltv_delta?: number;
        /** Fee Rate In Millitokens Per Million */
        fee_rate?: number;
        /** Edge is Disabled */
        is_disabled?: boolean;
        /** Maximum HTLC Millitokens */
        max_htlc_mtokens?: string;
        /** Minimum HTLC Millitokens */
        min_htlc_mtokens?: string;
        /** Public Key */
        public_key: string;
        /** Last Update Epoch ISO 8601 Date */
        updated_at?: string;
      }[];
      /** Funding Transaction Id */
      transaction_id: string;
      /** Funding Transaction Output Index */
      transaction_vout: number;
      /** Last Update Epoch ISO 8601 Date */
      updated_at?: string;
    }[];
    nodes: {
      /** Name */
      alias: string;
      /** Hex Encoded Color */
      color: string;
      features: {
        /** BOLT 09 Feature Bit */
        bit: number;
        /** Feature is Known */
        is_known: boolean;
        /** Feature Support is Required */
        is_required: boolean;
        /** Feature Type */
        type: string;
      }[];
      /** Node Public Key */
      public_key: string;
      /** Network Address and Port */
      sockets: string;
      /** Last Updated ISO 8601 Date */
      updated_at: string;
    }[];
  };

  /**
   * Get the network graph
   *
   * Requires `info:read` permission
   */
  export const getNetworkGraph: LNDMethod<
    GetNetworkGraphArgs,
    GetNetworkGraphResult
  >;

  export type GetNetworkInfoArgs = {};

  export type GetNetworkInfoResult = {
    /** Tokens */
    average_channel_size: number;
    /** Channels Count */
    channel_count: number;
    /** Tokens */
    max_channel_size: number;
    /** Median Channel Tokens */
    median_channel_size: number;
    /** Tokens */
    min_channel_size: number;
    /** Node Count */
    node_count: number;
    /** Channel Edge Count */
    not_recently_updated_policy_count: number;
    /** Total Capacity */
    total_capacity: number;
  };

  /**
   * Get network info
   *
   * Requires `info:read` permission
   */
  export const getNetworkInfo: LNDMethod<
    GetNetworkInfoArgs,
    GetNetworkInfoResult
  >;

  export type GetNodeArgs = {
    /** Omit Channels from Node */
    is_omitting_channels?: boolean;
    /** Node Public Key Hex */
    public_key: string;
  };

  export type GetNodeResult = {
    /** Node Alias */
    alias: string;
    /** Node Total Capacity Tokens */
    capacity: number;
    /** Known Node Channels */
    channel_count: number;
    channels?: {
      /** Maximum Tokens */
      capacity: number;
      /** Standard Format Channel Id */
      id: string;
      policies: {
        /** Base Fee Millitokens */
        base_fee_mtokens?: string;
        /** Locktime Delta */
        cltv_delta?: number;
        /** Fees Charged Per Million Millitokens */
        fee_rate?: number;
        /** Channel Is Disabled */
        is_disabled?: boolean;
        /** Maximum HTLC Millitokens Value */
        max_htlc_mtokens?: string;
        /** Minimum HTLC Millitokens Value */
        min_htlc_mtokens?: string;
        /** Node Public Key */
        public_key: string;
        /** Policy Last Updated At ISO 8601 Date */
        updated_at?: string;
      }[];
      /** Transaction Id Hex */
      transaction_id: string;
      /** Transaction Output Index */
      transaction_vout: number;
      /** Channel Last Updated At ISO 8601 Date */
      updated_at?: string;
    }[];
    /** RGB Hex Color */
    color: string;
    features: {
      /** BOLT 09 Feature Bit */
      bit: number;
      /** Feature is Known */
      is_known: boolean;
      /** Feature Support is Required */
      is_required: boolean;
      /** Feature Type */
      type: string;
    }[];
    sockets: {
      /** Host and Port */
      socket: string;
      /** Socket Type */
      type: string;
    }[];
    /** Last Known Update ISO 8601 Date */
    updated_at?: string;
  };

  /**
   * Get information about a node
   * Requires `info:read` permission
   */
  export const getNode: LNDMethod<GetNodeArgs, GetNodeResult>;

  export type GetPaymentArgs = {
    /** Payment Preimage Hash Hex */
    id: string;
  };

  export type GetPaymentResult = {
    failed?: {
      /** Failed Due To Lack of Balance */
      is_insufficient_balance: boolean;
      /** Failed Due to Payment Rejected At Destination */
      is_invalid_payment: boolean;
      /** Failed Due to Pathfinding Timeout */
      is_pathfinding_timeout: boolean;
      /** Failed Due to Absence of Path Through Graph */
      is_route_not_found: boolean;
    };
    /** Payment Is Settled */
    is_confirmed?: boolean;
    /** Payment Is Failed */
    is_failed?: boolean;
    /** Payment Is Pending */
    is_pending?: boolean;
    payment?: {
      /** Total Fee Millitokens To Pay */
      fee_mtokens: string;
      hops: {
        /** Standard Format Channel Id */
        channel: string;
        /** Channel Capacity Tokens */
        channel_capacity: number;
        /** Routing Fee Tokens */
        fee: number;
        /** Fee Millitokens */
        fee_mtokens: string;
        /** Forwarded Tokens */
        forward: number;
        /** Forward Millitokens */
        forward_mtokens: string;
        /** Public Key Hex */
        public_key: string;
        /** Timeout Block Height */
        timeout: number;
      }[];
      /** Payment Hash Hex */
      id: string;
      /** Total Millitokens Paid */
      mtokens: string;
      /** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number;
      /** Payment Tokens Rounded Up */
      safe_tokens: number;
      /** Payment Preimage Hex */
      secret: string;
      /** Expiration Block Height */
      timeout: number;
      /** Total Tokens Paid */
      tokens: number;
    };
  };

  /**
   * Get the status of a past payment
   *
   * Requires `offchain:read` permissio
   */
  export const getPayment: LNDMethod<GetPaymentArgs, GetPaymentResult>;

  export type GetPaymentsArgs = {
    /** Page Result Limit */
    limit?: number;
    /** Opaque Paging Token */
    token?: string;
  };

  export type GetPaymentsResult = {
    payments: {
      attempts: {
        failure?: {
          /** Error Type Code */
          code: number;
          details?: {
            /** Standard Format Channel Id */
            channel?: string;
            /** Error Associated Block Height */
            height?: number;
            /** Failed Hop Index */
            index?: number;
            /** Error Millitokens */
            mtokens?: string;
            policy?: {
              /** Base Fee Millitokens */
              base_fee_mtokens: string;
              /** Locktime Delta */
              cltv_delta: number;
              /** Fees Charged Per Million Tokens */
              fee_rate: number;
              /** Channel is Disabled */
              is_disabled?: boolean;
              /** Maximum HLTC Millitokens Value */
              max_htlc_mtokens: string;
              /** Minimum HTLC Millitokens Value */
              min_htlc_mtokens: string;
              /** Updated At ISO 8601 Date */
              updated_at: string;
            };
            /** Error CLTV Timeout Height */
            timeout_height?: number;
            update?: {
              /** Chain Id Hex */
              chain: string;
              /** Channel Flags */
              channel_flags: number;
              /** Extra Opaque Data Hex */
              extra_opaque_data: string;
              /** Message Flags */
              message_flags: number;
              /** Channel Update Signature Hex */
              signature: string;
            };
          };
          /** Error Message */
          message: string;
        };
        /** Payment Attempt Succeeded */
        is_confirmed: boolean;
        /** Payment Attempt Failed */
        is_failed: boolean;
        /** Payment Attempt is Waiting For Resolution */
        is_pending: boolean;
        route: {
          /** Route Fee Tokens */
          fee: number;
          /** Route Fee Millitokens */
          fee_mtokens: string;
          hops: {
            /** Standard Format Channel Id */
            channel: string;
            /** Channel Capacity Tokens */
            channel_capacity: number;
            /** Fee */
            fee: number;
            /** Fee Millitokens */
            fee_mtokens: string;
            /** Forward Tokens */
            forward: number;
            /** Forward Millitokens */
            forward_mtokens: string;
            /** Forward Edge Public Key Hex */
            public_key?: string;
            /** Timeout Block Height */
            timeout?: number;
          }[];
          /** Total Fee-Inclusive Millitokens */
          mtokens: string;
          /** Payment Identifier Hex */
          payment?: string;
          /** Timeout Block Height */
          timeout: number;
          /** Total Fee-Inclusive Tokens */
          tokens: number;
          /** Total Millitokens */
          total_mtokens?: string;
        };
      }[];
      /** Payment at ISO-8601 Date */
      created_at: string;
      /** Destination Node Public Key Hex */
      destination: string;
      /** Paid Routing Fee Rounded Down Tokens */
      fee: number;
      /** Paid Routing Fee in Millitokens */
      fee_mtokens: string;
      /** First Route Hop Public Key Hex */
      hops: string;
      /** Payment Preimage Hash */
      id: string;
      /** Payment Add Index */
      index?: number;
      /** Payment is Confirmed */
      is_confirmed: boolean;
      /** Transaction Is Outgoing */
      is_outgoing: boolean;
      /** Millitokens Sent to Destination */
      mtokens: string;
      /** BOLT 11 Payment Request */
      request?: string;
      /** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number;
      /** Payment Tokens Rounded Up */
      safe_tokens: number;
      /** Payment Preimage Hex */
      secret: string;
      /** Rounded Down Tokens Sent to Destination */
      tokens: number;
    }[];
    /** Next Opaque Paging Token */
    next?: string;
  };

  /**
   * Get payments made through channels.
   *
   * Requires `offchain:read` permission
   */
  export const getPayments: LNDMethod<GetPaymentsArgs, GetPaymentsResult>;

  export type GetPeersArgs = {};

  export type GetPeersResult = {
    peers: {
      /** Bytes Received */
      bytes_received: number;
      /** Bytes Sent */
      bytes_sent: number;
      features: {
        /** BOLT 09 Feature Bit */
        bit: number;
        /** Feature is Known */
        is_known: boolean;
        /** Feature Support is Required */
        is_required: boolean;
        /** Feature Type */
        type: string;
      }[];
      /** Is Inbound Peer */
      is_inbound: boolean;
      /** Is Syncing Graph Data */
      is_sync_peer?: boolean;
      /** Peer Last Reconnected At ISO 8601 Date */
      last_reconnected?: string;
      /** Ping Latency Milliseconds */
      ping_time: number;
      /** Node Identity Public Key */
      public_key: string;
      /** Count of Reconnections Over Time */
      reconnection_rate?: number;
      /** Network Address And Port */
      socket: string;
      /** Amount Received Tokens */
      tokens_received: number;
      /** Amount Sent Tokens */
      tokens_sent: number;
    }[];
  };

  /**
   * Get connected peers.
   *
   * Requires `peers:read` permission
   *
   * LND 0.11.1 and below do not return `last_reconnected` or `reconnection_rate
   */
  export const getPeers: LNDMethod<GetPeersArgs, GetPeersResult>;

  export type GetPendingChainBalanceArgs = {};

  export type GetPendingChainBalanceResult = {
    /** Pending Chain Balance Tokens */
    pending_chain_balance: number;
  };

  /**
   * Get pending chain balance in simple unconfirmed outputs.
   *
   * Pending channels limbo balance is not included
   *
   * Requires `onchain:read` permission
   */
  export const getPendingChainBalance: LNDMethod<
    GetPendingChainBalanceArgs,
    GetPendingChainBalanceResult
  >;

  export type GetPendingChannelsArgs = {};

  export type GetPendingChannelsResult = {
    pending_channels: {
      /** Channel Closing Transaction Id */
      close_transaction_id?: string;
      /** Channel Is Active */
      is_active: boolean;
      /** Channel Is Closing */
      is_closing: boolean;
      /** Channel Is Opening */
      is_opening: boolean;
      /** Channel Partner Initiated Channel */
      is_partner_initiated?: boolean;
      /** Channel Local Tokens Balance */
      local_balance: number;
      /** Channel Local Reserved Tokens */
      local_reserve: number;
      /** Channel Peer Public Key */
      partner_public_key: string;
      /** Tokens Pending Recovery */
      pending_balance?: number;
      pending_payments?: {
        /** Payment Is Incoming */
        is_incoming: boolean;
        /** Payment Timelocked Until Height */
        timelock_height: number;
        /** Payment Tokens */
        tokens: number;
        /** Payment Transaction Id */
        transaction_id: string;
        /** Payment Transaction Vout */
        transaction_vout: number;
      }[];
      /** Tokens Received */
      received: number;
      /** Tokens Recovered From Close */
      recovered_tokens?: number;
      /** Remote Tokens Balance */
      remote_balance: number;
      /** Channel Remote Reserved Tokens */
      remote_reserve: number;
      /** Send Tokens */
      sent: number;
      /** Pending Tokens Block Height Timelock */
      timelock_expiration?: number;
      /** Funding Transaction Fee Tokens */
      transaction_fee?: number;
      /** Channel Funding Transaction Id */
      transaction_id: string;
      /** Channel Funding Transaction Vout */
      transaction_vout: number;
      /** Funding Transaction Weight */
      transaction_weight?: number;
    }[];
  };

  /**
   * Get pending channels.
	 * 
	 * Both `is_closing` and `is_opening` are returned as part of a channel because a
channel may be opening, closing, or active.
	 * 
	 * Requires `offchain:read` permission
   */
  export const getPendingChannels: LNDMethod<
    GetPendingChannelsArgs,
    GetPendingChannelsResult
  >;

  export type GetPublicKeyArgs = {
    /** Key Family */
    family: number;
    /** Key Index */
    index?: number;
  };

  export type GetPublicKeyResult = {
    /** Key Index */
    index: number;
    /** Public Key Hex */
    public_key: string;
  };

  /**
   * Get a public key in the seed
   *
   * Omit a key index to cycle to the "next" key in the family
   *
   * Requires LND compiled with `walletrpc` build tag
   *
   * Requires `address:read` permission
   */
  export const getPublicKey: LNDMethod<GetPublicKeyArgs, GetPublicKeyResult>;

  export type GetRouteConfidenceArgs = {
    /** Starting Hex Serialized Public Key */
    from?: string;
    hops: {
      /** Forward Millitokens */
      forward_mtokens: string;
      /** Forward Edge Public Key Hex */
      public_key: string;
    }[];
  };

  export type GetRouteConfidenceResult = {
    /** Confidence Score Out Of One Million */
    confidence: number;
  };

  /**
   * Get routing confidence of successfully routing a payment to a destination
   *
   * If `from` is not set, self is default
   *
   * Requires `offchain:read` permission
   */
  export const getRouteConfidence: LNDMethod<
    GetRouteConfidenceArgs,
    GetRouteConfidenceResult
  >;

  export type GetRouteThroughHopsArgs = {
    /** Final CLTV Delta */
    cltv_delta?: number;
    /** Millitokens to Send */
    mtokens?: string;
    /** Outgoing Channel Id */
    outgoing_channel?: string;
    messages?: {
      /** Message Type number */
      type: string;
      /** Message Raw Value Hex Encoded */
      value: string;
    }[];
    /** Payment Identifier Hex */
    payment?: string;
    /** Public Key Hex */
    public_keys: string;
    /** Tokens to Send */
    tokens?: number;
    /** Payment Total Millitokens */
    total_mtokens?: string;
  };

  export type GetRouteThroughHopsResult = {
    route: {
      /** Route Fee Tokens */
      fee: number;
      /** Route Fee Millitokens */
      fee_mtokens: string;
      hops: {
        /** Standard Format Channel Id */
        channel: string;
        /** Channel Capacity Tokens */
        channel_capacity: number;
        /** Fee */
        fee: number;
        /** Fee Millitokens */
        fee_mtokens: string;
        /** Forward Tokens */
        forward: number;
        /** Forward Millitokens */
        forward_mtokens: string;
        /** Forward Edge Public Key Hex */
        public_key: string;
        /** Timeout Block Height */
        timeout: number;
      }[];
      messages?: {
        /** Message Type number */
        type: string;
        /** Message Raw Value Hex Encoded */
        value: string;
      }[];
      /** Total Fee-Inclusive Millitokens */
      mtokens: string;
      /** Payment Identifier Hex */
      payment?: string;
      /** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number;
      /** Payment Tokens Rounded Up */
      safe_tokens: number;
      /** Route Timeout Height */
      timeout: number;
      /** Total Fee-Inclusive Tokens */
      tokens: number;
      /** Payment Total Millitokens */
      total_mtokens?: string;
    };
  };

  /**
   * Get an outbound route that goes through specific hops
   *
   * Requires `offchain:read` permission
   */
  export const getRouteThroughHops: LNDMethod<
    GetRouteThroughHopsArgs,
    GetRouteThroughHopsResult
  >;

  export type GetRouteToDestinationArgs = {
    /** Final CLTV Delta */
    cltv_delta?: number;
    /** Final Send Destination Hex Encoded Public Key */
    destination: string;
    features?: {
      /** Feature Bit */
      bit: number;
    }[];
    ignore?: {
      /** Channel Id */
      channel?: string;
      /** Public Key Hex */
      from_public_key: string;
      /** To Public Key Hex */
      to_public_key?: string;
    }[];
    /** Incoming Peer Public Key Hex */
    incoming_peer?: string;
    /** Ignore Past Failures */
    is_ignoring_past_failures?: boolean;
    /** Maximum Fee Tokens */
    max_fee?: number;
    /** Maximum Fee Millitokens */
    max_fee_mtokens?: string;
    /** Max CLTV Timeout */
    max_timeout_height?: number;
    messages?: {
      /** Message To Final Destination Type number */
      type: string;
      /** Message To Final Destination Raw Value Hex Encoded */
      value: string;
    }[];
    /** Tokens to Send */
    mtokens?: string;
    /** Outgoing Channel Id */
    outgoing_channel?: string;
    /** Payment Identifier Hex */
    payment?: string;
    routes?: [
      {
        /** Base Routing Fee In Millitokens */
        base_fee_mtokens?: string;
        /** Standard Format Channel Id */
        channel?: string;
        /** Channel Capacity Tokens */
        channel_capacity?: number;
        /** CLTV Delta Blocks */
        cltv_delta?: number;
        /** Fee Rate In Millitokens Per Million */
        fee_rate?: number;
        /** Forward Edge Public Key Hex */
        public_key: string;
      }[]
    ];
    /** Starting Node Public Key Hex */
    start?: string;
    /** Tokens */
    tokens?: number;
    /** Total Millitokens of Shards */
    total_mtokens?: string;
  };

  export type GetRouteToDestinationResult = {
    route?: {
      /** Route Confidence Score Out Of One Million */
      confidence?: number;
      /** Route Fee Tokens */
      fee: number;
      /** Route Fee Millitokens */
      fee_mtokens: string;
      hops: {
        /** Standard Format Channel Id */
        channel: string;
        /** Channel Capacity Tokens */
        channel_capacity: number;
        /** Fee */
        fee: number;
        /** Fee Millitokens */
        fee_mtokens: string;
        /** Forward Tokens */
        forward: number;
        /** Forward Millitokens */
        forward_mtokens: string;
        /** Forward Edge Public Key Hex */
        public_key: string;
        /** Timeout Block Height */
        timeout: number;
      }[];
      messages?: {
        /** Message Type number */
        type: string;
        /** Message Raw Value Hex Encoded */
        value: string;
      }[];
      /** Total Fee-Inclusive Millitokens */
      mtokens: string;
      /** Payment Forwarding Fee Rounded Up Tokens */
      safe_fee: number;
      /** Payment Tokens Rounded Up */
      safe_tokens: number;
      /** Route Timeout Height */
      timeout: number;
      /** Total Fee-Inclusive Tokens */
      tokens: number;
    };
  };

  /**
   * Get a route to a destination.
   *
   * Call this iteratively after failed route attempts to get new routes
   *
   * Requires `info:read` permission
   */
  export const getRouteToDestination: LNDMethod<
    GetRouteToDestinationArgs,
    GetRouteToDestinationResult
  >;

  export type GetSweepTransactionsArgs = {};

  export type GetSweepTransactionsResult = {
    transactions: {
      /** Block Hash */
      block_id?: string;
      /** Confirmation Count */
      confirmation_count?: number;
      /** Confirmation Block Height */
      confirmation_height?: number;
      /** Created ISO 8601 Date */
      created_at: string;
      /** Fees Paid Tokens */
      fee?: number;
      /** Transaction Id */
      id: string;
      /** Is Confirmed */
      is_confirmed: boolean;
      /** Transaction Outbound */
      is_outgoing: boolean;
      /** Address */
      output_addresses: string;
      spends: {
        /** Output Tokens */
        tokens?: number;
        /** Spend Transaction Id Hex */
        transaction_id: string;
        /** Spend Transaction Output Index */
        transaction_vout: number;
      }[];
      /** Tokens Including Fee */
      tokens: number;
      /** Raw Transaction Hex */
      transaction?: string;
    }[];
  };

  /**
   * Get self-transfer spend transactions related to channel closes
   *
   * Requires `onchain:read` permissio
   */
  export const getSweepTransactions: LNDMethod<
    GetSweepTransactionsArgs,
    GetSweepTransactionsResult
  >;

  export type GetTowerServerInfoArgs = {};

  export type GetTowerServerInfoResult = {
    tower?: {
      /** Watchtower Server Public Key Hex */
      public_key: string;
      /** Socket */
      sockets: string;
      /** Watchtower External URI */
      uris: string;
    };
  };

  /**
   * Get watchtower server info.
   * This method requires LND built with `watchtowerrpc` build tag
   * Requires `info:read` permission
   */
  export const getTowerServerInfo: LNDMethod<
    GetTowerServerInfoArgs,
    GetTowerServerInfoResult
  >;

  export type GetUtxosArgs = {
    /** Maximum Confirmations */
    max_confirmations?: number;
    /** Minimum Confirmations */
    min_confirmations?: number;
  };

  export type GetUtxosResult = {
    utxos: {
      /** Chain Address */
      address: string;
      /** Chain Address Format */
      address_format: string;
      /** Confirmation Count */
      confirmation_count: number;
      /** Output Script Hex */
      output_script: string;
      /** Unspent Tokens */
      tokens: number;
      /** Transaction Id Hex */
      transaction_id: string;
      /** Transaction Output Index */
      transaction_vout: number;
    }[];
  };

  /**
   * Get unspent transaction outputs
   * Requires `onchain:read` permission
   */
  export const getUtxos: LNDMethod<GetUtxosArgs, GetUtxosResult>;

  export type GetWalletInfoArgs = {};

  export type GetWalletInfoResult = {
    /** Active Channels Count */
    active_channels_count: number;
    /** Node Alias */
    alias: string;
    /** Chain Id Hex */
    chains: string;
    /** Node Color */
    color: string;
    /** Best Chain Hash Hex */
    current_block_hash: string;
    /** Best Chain Height */
    current_block_height: number;
    features: {
      /** BOLT 09 Feature Bit */
      bit: number;
      /** Feature is Known */
      is_known: boolean;
      /** Feature Support is Required */
      is_required: boolean;
      /** Feature Type */
      type: string;
    }[];
    /** Is Synced To Chain */
    is_synced_to_chain: boolean;
    /** Latest Known Block At Date */
    latest_block_at: string;
    /** Peer Count */
    peers_count: number;
    /** Pending Channels Count */
    pending_channels_count: number;
    /** Public Key */
    public_key: string;
  };

  /**
   * Get overall wallet info.
   *
   * Requires `info:read` permission
   */
  export const getWalletInfo: LNDMethod<GetWalletInfoArgs, GetWalletInfoResult>;

  export type GetWalletVersionArgs = {};

  export type GetWalletVersionResult = {
    /** Build Tag */
    build_tags: string[];
    /** Commit SHA1 160 Bit Hash Hex */
    commit_hash: string;
    /** Is Autopilot RPC Enabled */
    is_autopilotrpc_enabled: boolean;
    /** Is Chain RPC Enabled */
    is_chainrpc_enabled: boolean;
    /** Is Invoices RPC Enabled */
    is_invoicesrpc_enabled: boolean;
    /** Is Sign RPC Enabled */
    is_signrpc_enabled: boolean;
    /** Is Wallet RPC Enabled */
    is_walletrpc_enabled: boolean;
    /** Is Watchtower Server RPC Enabled */
    is_watchtowerrpc_enabled: boolean;
    /** Is Watchtower Client RPC Enabled */
    is_wtclientrpc_enabled: boolean;
    /** Recognized LND Version */
    version?: string;
  };

  /**
   * Get wallet version
   *
   * Tags are self-reported by LND and are not guaranteed to be accurate
   *
   * Requires `info:read` permissio
   */
  export const getWalletVersion: LNDMethod<
    GetWalletVersionArgs,
    GetWalletVersionResult
  >;

  export type GrantAccessArgs = {
    /** Macaroon Id Positive Numeric */
    id?: string;
    /** Can Add or Remove Peers */
    is_ok_to_adjust_peers?: boolean;
    /** Can Make New Addresses */
    is_ok_to_create_chain_addresses?: boolean;
    /** Can Create Lightning Invoices */
    is_ok_to_create_invoices?: boolean;
    /** Can Create Macaroons */
    is_ok_to_create_macaroons?: boolean;
    /** Can Derive Public Keys */
    is_ok_to_derive_keys?: boolean;
    /** Can List Access Ids */
    is_ok_to_get_access_ids?: boolean;
    /** Can See Chain Transactions */
    is_ok_to_get_chain_transactions?: boolean;
    /** Can See Invoices */
    is_ok_to_get_invoices?: boolean;
    /** Can General Graph and Wallet Information */
    is_ok_to_get_wallet_info?: boolean;
    /** Can Get Historical Lightning Transactions */
    is_ok_to_get_payments?: boolean;
    /** Can Get Node Peers Information */
    is_ok_to_get_peers?: boolean;
    /** Can Send Funds or Edit Lightning Payments */
    is_ok_to_pay?: boolean;
    /** Can Revoke Access Ids */
    is_ok_to_revoke_access_ids?: boolean;
    /** Can Send Coins On Chain */
    is_ok_to_send_to_chain_addresses?: boolean;
    /** Can Sign Bytes From Node Keys */
    is_ok_to_sign_bytes?: boolean;
    /** Can Sign Messages From Node Key */
    is_ok_to_sign_messages?: boolean;
    /** Can Terminate Node or Change Operation Mode */
    is_ok_to_stop_daemon?: boolean;
    /** Can Verify Signatures of Bytes */
    is_ok_to_verify_bytes_signatures?: boolean;
    /** Can Verify Messages From Node Keys */
    is_ok_to_verify_messages?: boolean;
    /** Entity:Action */
    permissions?: string[];
  };

  export type GrantAccessResult = {
    /** Base64 Encoded Macaroon */
    macaroon: string;
    /** Entity:Action */
    permissions: string[];
  };

  /**
	 * Give access to the node by making a macaroon access credential
	 * 
	 * Specify `id` to allow for revoking future access
	 *
	 * Requires `macaroon:generate` permission
	 *
	 * Note: access once given cannot be revoked. Access is defined at the LND level
and version differences in LND can result in expanded access.
	 *
	 * Note: `id` is not supported in LND versions 0.11.0 and below
	 */
  export const grantAccess: LNDMethod<GrantAccessArgs, GrantAccessResult>;

  export type GRPCProxyServerArgs = {
    /** Bind to Address */
    bind?: string;
    /** LND Cert Base64 */
    cert?: string;
    /** Log Function */
    log: (output: string) => void;
    /** Router Path */
    path: string;
    /** Listen Port */
    port: number;
    /** LND Socket */
    socket: string;
    /** Log Write Stream */
    stream: stream.Writable;
  };

  export type GRPCProxyServerResult = {};

  /**
   * Get a gRPC proxy server
   */
  export const grpcProxyServer: LNDMethod<
    GRPCProxyServerArgs,
    GRPCProxyServerResult
  >;
}
