import dotenv from "dotenv"
import { IdentityWallet } from './identity';
import { BjjProvider, Ed25519Provider, InMemoryPrivateKeyStore, KMS, KmsKeyType, LocalStoragePrivateKeyStore, Sec256k1Provider } from './kms';
import { CredentialStatusResolverRegistry } from './credentials/status/resolver';
import { CredentialStatusType, VerifiableConstants, W3CCredential } from './verifiable';
import { CredentialRequest, CredentialWallet, RHSResolver } from './credentials';
import { ethers, id, JsonRpcProvider } from 'ethers';
import { DidMethod, Blockchain, NetworkId } from '@iden3/js-iden3-core';
import { CredentialStorage, defaultEthConnectionConfig, EthConnectionConfig, EthStateStorage, Identity, IdentityStorage, InMemoryDataSource, InMemoryMerkleTreeStorage, IStateStorage, Profile, RootInfo, StateProof } from './storage';
import { getRandomBytes } from "@iden3/js-crypto";

export const RHS_URL = 'https://rhs-staging.polygonid.me';

export const registerKeyProvidersInMemoryKMS = (): KMS => {
  const memoryKeyStore = new InMemoryPrivateKeyStore();
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);
  const sec256k1Provider = new Sec256k1Provider(KmsKeyType.Secp256k1, memoryKeyStore);
  kms.registerKeyProvider(KmsKeyType.Secp256k1, sec256k1Provider);
  return kms;
};

export const getInMemoryDataStorage = (states: IStateStorage) => {
  return {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40), 
    states
  };
};

const seed = getRandomBytes(32)

const run = async () => {
  const kms = new KMS();
  
  const ethStateStore = new EthStateStorage({
    ...defaultEthConnectionConfig,
    chainId: 80002,
    url: 'https://polygon-amoy.g.alchemy.com/v2/MAGo0Nsn4wbqRxj73U8Y_EaPwvD8lG9h',
    contractAddress: "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124",
    maxFeePerGas: '28000000000',
    maxPriorityFeePerGas: "26000000000"
  })

  const localKeyStore = new LocalStoragePrivateKeyStore();
  const ed25519Provider = new Ed25519Provider(KmsKeyType.Ed25519, localKeyStore);

  kms.registerKeyProvider(KmsKeyType.Ed25519, ed25519Provider);

  const dataStorage = getInMemoryDataStorage(ethStateStore);
  const resolvers = new CredentialStatusResolverRegistry();
  resolvers.register(
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    new RHSResolver(dataStorage.states)
  );
  const credWallet = new CredentialWallet(dataStorage, resolvers);
  const idWallet = new IdentityWallet(registerKeyProvidersInMemoryKMS(), dataStorage, credWallet);

  const provider = new ethers.JsonRpcProvider('https://polygon-amoy.g.alchemy.com/v2/MAGo0Nsn4wbqRxj73U8Y_EaPwvD8lG9h');
  const wallet = new ethers.Wallet('0xb01fd5c36dc5d21e4e6ddeda1ea79183e483fd450d6a3077d47ede81d6319f17', provider);
  const signer = wallet.connect(provider);
  const address = await signer.getAddress();
  
  const ethSigner = new ethers.Wallet('0xb01fd5c36dc5d21e4e6ddeda1ea79183e483fd450d6a3077d47ede81d6319f17', provider);
  

  const createClaimReq = (
    credentialSubjectId: string,
    address: string,
    opts?: Partial<CredentialRequest>
  ): CredentialRequest => {
    return {
      credentialSchema:
      "https://gist.githubusercontent.com/pavankpdev/d603e78d83b36aa14c269f5e3cd46881/raw/b72db6f10363506aa668fa062fba57defedf8271/walletholderverification.json",
      type: 'walletholderverification',
      credentialSubject: {
        id: credentialSubjectId,
        wallet: address,
      },
      expiration: 12345678888,
      revocationOpts: {
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        id: RHS_URL
      },
      ...opts
    };
  };

  const d = await idWallet.createEthereumBasedIdentity({
    seed,
    ethSigner: ethSigner,
    method: DidMethod.Iden3,
    blockchain: Blockchain.Polygon,
    networkId: NetworkId.Amoy,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: RHS_URL
    }
  });

  console.log(d);

  // console.log(d.did.string(), address);
  

  // const creds = await idWallet.issueCredential(
  //   d.did,
  //   createClaimReq(d.did.string(), address)
  // )

  console.log(d);
  // console.log(creds);
  
};

// dotenv.config();

run();