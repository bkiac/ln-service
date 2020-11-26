/**
 * TODO:
 * - errors
 * - callbacks
 */

declare module "ln-service" {
  type LND = {
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

  type LNService = {
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

  const lnService: LNService;
  export default lnService;

  /**
   * Add a peer if possible (not self, or already connected)
   *
   * Requires `peers:write` permission
   *
   * `timeout` is not supported in LND 0.11.1 and below
   *
   * See: https://github.com/alexbosworth/ln-service#addpeer
   */
  export function addPeer(variables: {
    /** Add Peer as Temporary Peer Bool, default: `false` */
    is_temporary?: boolean;
    /** Authenticated LND API Object */
    lnd: LND;
    /** Public Key Hex String */
    public_key: string;
    /** Retry Count Number */
    retry_count?: number;
    /** Delay Retry By Milliseconds Number */
    retry_delay?: number;
    /** Host Network Address And Optional Port String>, ip:port */
    socket: string;
    /** Connection Attempt Timeout Milliseconds Number */
    timeout?: number;
  }): Promise<void>;

  export function addPeer(
    variables: any,
    callback: (err: Error, result: any) => void
  );

  /**
   * Publish a raw blockchain transaction to Blockchain network peers
   *
   * Requires LND built with `walletrpc` tag
   *
   * See: https://github.com/alexbosworth/ln-service#broadcastchaintransaction
   */
  export function broadcastChainTransaction(variables: {
    /** Transaction Label String */
    description?: string;
    /** Authenticated LND API Object */
    lnd: LND;
    /** Transaction Hex String */
    transaction: string;
  }): Promise<{
    /** Transaction Id Hex String */
    id: string;
  }>;

  export type ChannelPolicy = {
    /** Base Fee Millitokens String */
    base_fee_mtokens: string;
    /** CLTV Delta Number */
    cltv_delta: number;
    /** Fee Rate Number */
    fee_rate: number;
    /** Channel is Disabled Bool */
    is_disabled: boolean;
    /** Maximum HTLC Millitokens String */
    max_htlc_mtokens: string;
    /** Minimum HTLC Millitokens String */
    min_htlc_mtokens: string;
    /** Public Key Hex String */
    public_key: string;
  };
  export type Channel = {
    /** Capacity Tokens Number */
    capacity: number;
    /** Standard Channel Id String */
    id: string;
    policies: ChannelPolicy[];
  };

  export type Hop = {
    base_fee_mtokens: string;
    channel: string;
    channel_capacity: number;
    cltv_delta: number;
    fee_rate: number;
    public_key: string;
  };

  /**
   * Calculate hops between start and end nodes
   *
   * See: https://github.com/alexbosworth/ln-service#calculatehops
   */
  export function calculateHops(variables: {
    channels: Channel[];
    /** End Public Key Hex String */
    end: string;
    ignore?: {
      /** Standard Format Channel Id String */
      channel?: string;
      /** Public Key Hex String */
      public_key: string;
    }[];
    /** Millitokens Number */
    mtokens: number;
    /** Start Public Key Hex String */
    start: string;
  }): Promise<{ hops?: Hop[] }>;

  /**
   * Calculate multiple routes to a destination
   *
   * See: https://github.com/alexbosworth/ln-service#calculatepaths
   */
  export function calculatePaths(variables: {
    channels: Channel[];
    /** End Public Key Hex String */
    end: string;
    /** Paths To Return Limit Number */
    limit?: number;
    /** Millitokens Number */
    mtokens: number;
    /** Start Public Key Hex String */
    start: string;
  }): Promise<{ paths?: { hops: Hop[] }[] }>;

  /**
   * Cancel an invoice
   *
   * This call can cancel both HODL invoices and also void regular invoices
   *
   * Requires LND built with `invoicesrpc`
   *
   * Requires `invoices:write` permission
   *
   * See: https://github.com/alexbosworth/ln-service#cancelhodlinvoice
   *
   * TODO: return type?
   */
  export function cancelHodlInvoice(variables: {
    /** Payment Preimage Hash Hex String */
    id: string;
    /** Authenticated RPC LND API Object */
    lnd: LND;
  }): Promise<void>;

  /**
   * Cancel an external funding pending channel
   *
   * See: https://github.com/alexbosworth/ln-service#cancelpendingchannel
   *
   * TODO: return type?
   */
  export function cancelPendingChannel(variables: {
    /** Pending Channel Id Hex String */
    id: string;
    /** Authenticated LND API Object */
    lnd: LND;
  }): Promise<void>;

  /**
   * Change wallet password
   *
   * Requires locked LND and unauthenticated LND connection
   *
   * See: https://github.com/alexbosworth/ln-service#changepassword
   *
   * TODO: return type?
   */
  export function changePassword(variables: {
    current_password: string;
    lnd: LND;
    new_password: string;
  }): Promise<void>;

  /**
   * Close a channel.
   * Either an id or a transaction id / transaction output index is required
   *
   * If cooperatively closing, pass a public key and socket to connect
   *
   * Requires `info:read`, `offchain:write`, `onchain:write`, `peers:write` permissions
   *
   * See: https://github.com/alexbosworth/ln-service#closechannel
   */
  export function closeChannel(variables: {
    address?: string;
    id?: string;
    is_force_close?: boolean;
    lnd: LND;
    public_key?: string;
    socket?: string;
    target_confirmations?: number;
    tokens_per_vbyte?: number;
    transaction_id?: string;
    transaction_vout?: number;
  }): Promise<{
    transaction_id: string;
    transaction_vout: number;
  }>;

  /**
   * Connect to a watchtower
   *
   * This method requires LND built with `wtclientrpc` build tag
   *
   * Requires `offchain:write` permission
   *
   * See: https://github.com/alexbosworth/ln-service#connectwatchtower
   *
   * TODO: Return type?
   */
  export function connectWatchtower(variables: {
    /** Authenticated LND API Object */
    lnd: LND;
    /** Watchtower Public Key Hex String */
    public_key: string;
    /** Network Socket Address IP:PORT String */
    socket: string;
  }): Promise<void>;

  /**
   * Create a new receive address.
   *
   * Requires address:write permission
   *
   * See: https://github.com/alexbosworth/ln-service#createchainaddress
   *
   * TODO: Return type?
   */
  export function createChainAddress(variables: {
    /** Receive Address Type String */
    format: "np2wpkh" | "p2wpkh";
    /** Get As-Yet Unused Address Bool */
    is_unused?: boolean;
    /** Authenticated LND API Object */
    lnd: LND;
  }): Promise<{ address: any }>;

  /**
   * Create HODL invoice. This invoice will not settle automatically when an HTLC arrives. It must be settled separately with the secret preimage.
   *
   * Warning: make sure to cancel the created invoice before its CLTV timeout.
   *
   * Requires LND built with `invoicesrpc` tag
   *
   * Requires `address:write`, `invoices:write` permission
   *
   * See: https://github.com/alexbosworth/ln-service#createhodlinvoice
   */
  export function createHodlInvoice(variables: {
    /** Final CLTV Delta Number */
    cltv_delta?: number;
    /** Invoice Description String */
    description?: string;
    /** Hashed Description of Payment Hex String */
    description_hash?: string;
    /** Expires At ISO 8601 Date String */
    expires_at?: string;
    /** Payment Hash Hex String */
    id?: string;
    /** Is Fallback Address Included Bool */
    is_fallback_included?: boolean;
    /** Is Fallback Address Nested Bool */
    is_fallback_nested?: boolean;
    /** Invoice Includes Private Channels Bool */
    is_including_private_channels?: boolean;
    /** Authenticated LND API Object */
    lnd: LND;
    /** Millitokens String */
    mtokens?: string;
    /** Tokens Number */
    tokens?: number;
  }): Promise<{
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
  }>;
}
