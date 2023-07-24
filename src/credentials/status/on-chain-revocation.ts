import { RevocationStatus, CredentialStatus } from '../../verifiable';
import { EthConnectionConfig } from '../../storage/blockchain';
import { CredentialStatusResolver, CredentialStatusResolveOptions } from './resolver';
import { OnChainRevocationStorage } from '../../storage/blockchain/onchain-revocation';
import { DID } from '@iden3/js-iden3-core';

/**
 * OnChainIssuer is a class that allows to interact with the onchain contract
 * and build the revocation status.
 *
 * @public
 * @class OnChainIssuer
 */
export class OnChainResolver implements CredentialStatusResolver {
  /**
   *
   * Creates an instance of OnChainIssuer.
   * @public
   * @param {Array<EthConnectionConfig>} - onchain contract address
   * @param {string} - list of EthConnectionConfig
   */
  constructor(private readonly _configs: EthConnectionConfig[]) {}

  /**
   * resolve is a method to resolve a credential status from the blockchain.
   *
   * @public
   * @param {CredentialStatus} credentialStatus -  credential status to resolve
   * @param {CredentialStatusResolveOptions} credentialStatusResolveOptions -  options for resolver
   * @returns `{Promise<RevocationStatus>}`
   */
  async resolve(
    credentialStatus: CredentialStatus,
    credentialStatusResolveOptions?: CredentialStatusResolveOptions
  ): Promise<RevocationStatus> {
    if (!credentialStatusResolveOptions?.issuerDID) {
      throw new Error('IssuerDID is not set in options');
    }
    return this.getRevocationOnChain(credentialStatus, credentialStatusResolveOptions.issuerDID);
  }

  /**
   * Gets partial revocation status info from onchain issuer contract.
   *
   * @param {CredentialStatus} credentialStatus - credential status section of credential
   * @param {DID} issuerDid - issuer did
   * @returns `{Promise<RevocationStatus>}`
   */
  async getRevocationOnChain(
    credentialStatus: CredentialStatus,
    issuer: DID
  ): Promise<RevocationStatus> {
    const { contractAddress, chainId, revocationNonce } = this.parseOnChainId(credentialStatus.id);
    if (revocationNonce !== credentialStatus.revocationNonce) {
      throw new Error('revocationNonce does not match');
    }
    const networkConfig = this.networkByChainId(chainId);
    const onChainCaller = new OnChainRevocationStorage(networkConfig, contractAddress);
    const id = DID.idFromDID(issuer);
    const revocationStatus = await onChainCaller.getRevocationStatus(id.bigInt(), revocationNonce);
    return revocationStatus;
  }

  /**
   * Parse credentialStatus id to get contractAddress, chainId and revocationNonce
   *
   * @param {string} id - credential status id
   * @returns {{contractAddress: string, chainId: number, revocationNonce: number}}
   */
  parseOnChainId(id: string): {
    contractAddress: string;
    chainId: number;
    revocationNonce: number;
    issuer: string;
  } {
    const url = new URL(id);
    const contractId = url.searchParams.get('contractAddress');
    const revocationNonceParam = url.searchParams.get('revocationNonce');

    if (!contractId) {
      throw new Error('contractAddress not found');
    }
    if (!revocationNonceParam) {
      throw new Error('revocationNonce not found');
    }

    const issuer = id.split('/')[0];
    if (!issuer) {
      throw new Error('issuer not found in credentialStatus id');
    }

    // TODO (illia-korotia): after merging core v2 need to parse contract address from did if `contractAddress` is not present in id as param
    const revocationNonce = parseInt(revocationNonceParam, 10);
    const parts = contractId.split(':');
    if (parts.length != 2) {
      throw new Error('invalid contract address');
    }
    const chainId = parseInt(parts[0], 10);
    const contractAddress = parts[1];

    return { contractAddress, chainId, revocationNonce, issuer };
  }

  networkByChainId(chainId: number): EthConnectionConfig {
    const network = this._configs.find((c) => c.chainId === chainId);
    if (!network) {
      throw new Error(`chainId "${chainId}" not supported`);
    }
    return network;
  }
}
