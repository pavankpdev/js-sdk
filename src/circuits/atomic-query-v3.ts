import { Claim, DID, getDateFromUnixTimestamp, Id, SchemaHash } from '@iden3/js-iden3-core';
import {
  BaseConfig,
  bigIntArrayToStringArray,
  prepareSiblingsStr,
  existenceToInt,
  getNodeAuxValue,
  prepareCircuitArrayValues,
  checkIssuerNonRevState,
  checkUserState,
  getResolverByID
} from './common';
import { BJJSignatureProof, CircuitError, MTProof, Query, ValueProof } from './models';
import { Hash, Proof, ZERO_HASH } from '@iden3/js-merkletree';
import { byteDecoder, byteEncoder } from '../utils';
import { ProofQuery, ProofType } from '../verifiable';
import { StateResolvers } from '../storage';
import { PubSignalsVerifier, VerifyOpts } from './pub-signal-verifier';
import { IDOwnershipPubSignals } from './ownership-verifier';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { JSONObject } from '../iden3comm';
import { checkQueryRequest, ClaimOutputs } from './query';

const zero = '0';

export interface ClaimWithSigAndMTPProof {
  issuerID: Id;
  claim: Claim;
  nonRevProof: MTProof;
  signatureProof?: BJJSignatureProof;
  incProof?: MTProof;
}
/**
 * AtomicQueryV3Inputs ZK private inputs for credentialAtomicQueryV3.circom
 *
 * @beta
 * @class AtomicQueryV3Inputs
 * @extends {BaseConfig}
 */
export class AtomicQueryV3Inputs extends BaseConfig {
  requestID!: bigint;
  id!: Id;
  profileNonce!: bigint;
  claimSubjectProfileNonce!: bigint;
  claim!: ClaimWithSigAndMTPProof;
  skipClaimRevocationCheck!: boolean;
  query!: Query;
  currentTimeStamp!: number;
  proofType!: ProofType;
  linkNonce!: bigint;
  verifierID?: Id;
  nullifierSessionID!: bigint;

  validate(): void {
    if (!this.requestID) {
      throw new Error(CircuitError.EmptyRequestID);
    }

    if (!this.claim.nonRevProof.proof) {
      throw new Error(CircuitError.EmptyClaimNonRevProof);
    }

    if (!this.query.values) {
      throw new Error(CircuitError.EmptyQueryValue);
    }

    if (!this.proofType) {
      throw new Error(CircuitError.InvalidProofType);
    }

    if (this.proofType === ProofType.BJJSignature) {
      if (!this.claim.signatureProof?.issuerAuthIncProof.proof) {
        throw new Error(CircuitError.EmptyIssuerAuthClaimProof);
      }

      if (!this.claim.signatureProof.issuerAuthNonRevProof.proof) {
        throw new Error(CircuitError.EmptyIssuerAuthClaimNonRevProof);
      }

      if (!this.claim.signatureProof.signature) {
        throw new Error(CircuitError.EmptyClaimSignature);
      }
    }
    if (this.proofType === ProofType.Iden3SparseMerkleTreeProof) {
      if (!this.claim?.incProof?.proof) {
        throw new Error(CircuitError.EmptyClaimProof);
      }
    }
  }

  fillMTPProofsWithZero(s: Partial<AtomicQueryV3CircuitInputs>) {
    s.issuerClaimMtp = prepareSiblingsStr(new Proof(), this.getMTLevel());
    s.issuerClaimClaimsTreeRoot = ZERO_HASH.bigInt().toString();
    s.issuerClaimRevTreeRoot = ZERO_HASH.bigInt().toString();
    s.issuerClaimRootsTreeRoot = ZERO_HASH.bigInt().toString();
    s.issuerClaimIdenState = ZERO_HASH.bigInt().toString();
  }

  fillSigProofWithZero(s: Partial<AtomicQueryV3CircuitInputs>) {
    s.issuerClaimSignatureR8x = zero;
    s.issuerClaimSignatureR8y = zero;
    s.issuerClaimSignatureS = zero;
    s.issuerAuthClaim = new Claim().marshalJson();
    s.issuerAuthClaimMtp = prepareSiblingsStr(new Proof(), this.getMTLevel());
    s.issuerAuthClaimsTreeRoot = zero;
    s.issuerAuthRevTreeRoot = zero;
    s.issuerAuthRootsTreeRoot = zero;
    s.issuerAuthClaimNonRevMtp = prepareSiblingsStr(new Proof(), this.getMTLevel());

    s.issuerAuthClaimNonRevMtpAuxHi = ZERO_HASH.bigInt().toString();
    s.issuerAuthClaimNonRevMtpAuxHv = ZERO_HASH.bigInt().toString();
    s.issuerAuthClaimNonRevMtpNoAux = zero;
    s.issuerAuthState = zero;
  }

  // InputsMarshal returns Circom private inputs for credentialAtomicQueryV3.circom
  inputsMarshal(): Uint8Array {
    this.validate();

    if (this.query.valueProof) {
      this.query.validate();
      this.query.valueProof.validate();
    }

    let valueProof = this.query.valueProof;

    if (!valueProof) {
      valueProof = new ValueProof();
      valueProof.path = 0n;
      valueProof.value = 0n;
      valueProof.mtp = new Proof();
    }

    let treeState = this.claim.nonRevProof.treeState;
    if (this.proofType === ProofType.BJJSignature && this.skipClaimRevocationCheck) {
      treeState = this.claim.signatureProof?.issuerAuthNonRevProof.treeState;
    }

    if (!treeState) {
      throw new Error(CircuitError.EmptyTreeState);
    }

    const s: Partial<AtomicQueryV3CircuitInputs> = {
      requestID: this.requestID.toString(),
      userGenesisID: this.id.bigInt().toString(),
      profileNonce: this.profileNonce.toString(),
      claimSubjectProfileNonce: this.claimSubjectProfileNonce.toString(),
      issuerID: this.claim.issuerID.bigInt().toString(),
      issuerClaim: this.claim.claim.marshalJson(),

      issuerClaimNonRevClaimsTreeRoot: treeState.claimsRoot.bigInt().toString(),
      issuerClaimNonRevRevTreeRoot: treeState.revocationRoot.bigInt().toString(),
      issuerClaimNonRevRootsTreeRoot: treeState.rootOfRoots.bigInt().toString(),
      issuerClaimNonRevState: treeState.state.bigInt().toString(),
      issuerClaimNonRevMtp: prepareSiblingsStr(
        this.claim.nonRevProof.proof as Proof,
        this.getMTLevel()
      ),

      claimSchema: this.claim.claim.getSchemaHash().bigInt().toString(),

      claimPathMtp: prepareSiblingsStr(valueProof.mtp, this.getMTLevelsClaim()),
      claimPathValue: valueProof.value.toString(),
      operator: this.query.operator,
      timestamp: this.currentTimeStamp,
      // value in this path in merklized json-ld document

      slotIndex: this.query.slotIndex,
      isRevocationChecked: 1
    };

    if (this.skipClaimRevocationCheck) {
      s.isRevocationChecked = 0;
    }

    if (this.proofType === ProofType.BJJSignature) {
      s.proofType = '1';

      s.issuerClaimSignatureR8x = this.claim.signatureProof?.signature.R8[0].toString();
      s.issuerClaimSignatureR8y = this.claim.signatureProof?.signature.R8[1].toString();
      s.issuerClaimSignatureS = this.claim.signatureProof?.signature.S.toString();
      s.issuerAuthClaim = this.claim.signatureProof?.issuerAuthClaim?.marshalJson();
      s.issuerAuthClaimMtp = prepareSiblingsStr(
        this.claim.signatureProof?.issuerAuthIncProof.proof as Proof,
        this.getMTLevel()
      );

      s.issuerAuthClaimsTreeRoot = treeState.claimsRoot.bigInt().toString();
      s.issuerAuthRevTreeRoot = treeState.revocationRoot.bigInt().toString();
      s.issuerAuthRootsTreeRoot = treeState.rootOfRoots.bigInt().toString();
      s.issuerAuthClaimNonRevMtp = prepareSiblingsStr(
        this.claim.signatureProof?.issuerAuthNonRevProof.proof as Proof,
        this.getMTLevel()
      );

      const nodeAuxIssuerAuthNonRev = getNodeAuxValue(
        this.claim.signatureProof?.issuerAuthNonRevProof.proof
      );
      s.issuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key.bigInt().toString();
      s.issuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value.bigInt().toString();
      s.issuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux;
      s.issuerAuthState = this.claim.signatureProof?.issuerAuthIncProof.treeState?.state
        .bigInt()
        .toString();

      this.fillMTPProofsWithZero(s);
    } else if (this.proofType === ProofType.Iden3SparseMerkleTreeProof) {
      s.proofType = '2';

      const incProofTreeState = this.claim.incProof?.treeState;

      if (!incProofTreeState) {
        throw new Error(CircuitError.EmptyTreeState);
      }

      s.issuerClaimMtp = prepareSiblingsStr(this.claim.incProof?.proof as Proof, this.getMTLevel());
      s.issuerClaimClaimsTreeRoot = incProofTreeState.claimsRoot.bigInt().toString();
      s.issuerClaimRevTreeRoot = incProofTreeState.revocationRoot.bigInt().toString();
      s.issuerClaimRootsTreeRoot = incProofTreeState.rootOfRoots.bigInt().toString();
      s.issuerClaimIdenState = incProofTreeState.state.bigInt().toString();

      this.fillSigProofWithZero(s);
    }

    const nodeAuxNonRev = getNodeAuxValue(this.claim.nonRevProof.proof);
    s.issuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key.bigInt().toString();
    s.issuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value.bigInt().toString();
    s.issuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux;

    s.claimPathNotExists = existenceToInt(valueProof.mtp.existence);
    const nodAuxJSONLD = getNodeAuxValue(valueProof.mtp);
    s.claimPathMtpNoAux = nodAuxJSONLD.noAux;
    s.claimPathMtpAuxHi = nodAuxJSONLD.key.bigInt().toString();
    s.claimPathMtpAuxHv = nodAuxJSONLD.value.bigInt().toString();

    s.claimPathKey = valueProof.path.toString();

    const values = prepareCircuitArrayValues(this.query.values, this.getValueArrSize());
    s.value = bigIntArrayToStringArray(values);

    s.linkNonce = this.linkNonce.toString();
    s.verifierID = this.verifierID?.bigInt().toString() ?? '0';
    s.nullifierSessionID = this.nullifierSessionID.toString();

    return byteEncoder.encode(JSON.stringify(s));
  }
}

/**
 * @beta
 * AtomicQueryV3CircuitInputs type represents credentialAtomicQueryV3.circom private inputs required by prover
 */
interface AtomicQueryV3CircuitInputs {
  requestID: string;
  // user data
  userGenesisID: string;
  profileNonce: string;
  claimSubjectProfileNonce: string;

  issuerID: string;
  // Claim
  issuerClaim: string[];
  issuerClaimNonRevClaimsTreeRoot: string;
  issuerClaimNonRevRevTreeRoot: string;
  issuerClaimNonRevRootsTreeRoot: string;
  issuerClaimNonRevState: string;
  issuerClaimNonRevMtp: string[];
  issuerClaimNonRevMtpAuxHi: string;
  issuerClaimNonRevMtpAuxHv: string;
  issuerClaimNonRevMtpNoAux: string;
  claimSchema: string;
  issuerClaimSignatureR8x: string;
  issuerClaimSignatureR8y: string;
  issuerClaimSignatureS: string;
  issuerAuthClaim: string[];
  issuerAuthClaimMtp: string[];
  issuerAuthClaimNonRevMtp: string[];
  issuerAuthClaimNonRevMtpAuxHi: string;
  issuerAuthClaimNonRevMtpAuxHv: string;
  issuerAuthClaimNonRevMtpNoAux: string;
  issuerAuthClaimsTreeRoot: string;
  issuerAuthRevTreeRoot: string;
  issuerAuthRootsTreeRoot: string;
  issuerAuthState: string;

  isRevocationChecked: number;
  // Query
  // JSON path
  claimPathNotExists: number; // 0 for inclusion, 1 for non-inclusion
  claimPathMtp: string[];
  claimPathMtpNoAux: string; // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
  claimPathMtpAuxHi: string; // 0 for inclusion proof
  claimPathMtpAuxHv: string; // 0 for inclusion proof
  claimPathKey: string; // hash of path in merklized json-ld document
  claimPathValue: string; // value in this path in merklized json-ld document

  operator: number;
  slotIndex: number;
  timestamp: number;
  value: string[];

  issuerClaimMtp: string[];
  issuerClaimClaimsTreeRoot: string;
  issuerClaimRevTreeRoot: string;
  issuerClaimRootsTreeRoot: string;
  issuerClaimIdenState: string;

  proofType: string;

  // Private random nonce, used to generate LinkID
  linkNonce: string;
  verifierID: string;
  nullifierSessionID: string;
}
/**
 * @beta
 * AtomicQueryV3PubSignals public inputs
 */
export class AtomicQueryV3PubSignals extends BaseConfig {
  requestID!: bigint;
  userID!: Id;
  issuerID!: Id;
  issuerState!: Hash;
  issuerClaimNonRevState!: Hash;
  claimSchema!: SchemaHash;
  slotIndex!: number;
  operator!: number;
  value: bigint[] = [];
  timestamp!: number;
  merklized!: number;
  claimPathKey!: bigint;
  claimPathNotExists!: number;
  isRevocationChecked!: number;
  proofType!: number;
  linkID!: bigint;
  nullifier!: bigint;
  operatorOutput!: bigint;
  verifierID!: Id;
  nullifierSessionID!: bigint;

  // PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals
  pubSignalsUnmarshal(data: Uint8Array): AtomicQueryV3PubSignals {
    // expected order:
    // merklized
    // userID
    // issuerState
    // linkID
    // nullifier
    // operatorOutput
    // proofType
    // requestID
    // issuerID
    // isRevocationChecked
    // issuerClaimNonRevState
    // timestamp
    // claimSchema
    // claimPathNotExists
    // claimPathKey
    // slotIndex
    // operator
    // value
    // verifierID
    // nullifierSessionID

    // 19 is a number of fields in AtomicQueryV3PubSignals before values, values is last element in the proof and
    // it is length could be different base on the circuit configuration. The length could be modified by set value
    // in ValueArraySize
    const fieldLength = 19;

    const sVals: string[] = JSON.parse(byteDecoder.decode(data));

    if (sVals.length !== fieldLength + this.getValueArrSize()) {
      throw new Error(
        `invalid number of Output values expected ${fieldLength + this.getValueArrSize()} got ${
          sVals.length
        }`
      );
    }

    let fieldIdx = 0;

    // -- merklized
    this.merklized = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    //  - userID
    this.userID = Id.fromBigInt(BigInt(sVals[fieldIdx]));
    fieldIdx++;

    // - issuerState
    this.issuerState = Hash.fromString(sVals[fieldIdx]);
    fieldIdx++;

    // - linkID
    this.linkID = BigInt(sVals[fieldIdx]);
    fieldIdx++;

    // - nullifier
    this.nullifier = BigInt(sVals[fieldIdx]);
    fieldIdx++;

    // - operatorOutput
    this.operatorOutput = BigInt(sVals[fieldIdx]);
    fieldIdx++;

    // - proofType
    this.proofType = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    // - requestID
    this.requestID = BigInt(sVals[fieldIdx]);
    fieldIdx++;

    // - issuerID
    this.issuerID = Id.fromBigInt(BigInt(sVals[fieldIdx]));
    fieldIdx++;

    // - isRevocationChecked
    this.isRevocationChecked = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    // - issuerClaimNonRevState
    this.issuerClaimNonRevState = Hash.fromString(sVals[fieldIdx]);
    fieldIdx++;

    //  - timestamp
    this.timestamp = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    //  - claimSchema
    this.claimSchema = SchemaHash.newSchemaHashFromInt(BigInt(sVals[fieldIdx]));
    fieldIdx++;

    // - ClaimPathNotExists
    this.claimPathNotExists = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    // - ClaimPathKey
    this.claimPathKey = BigInt(sVals[fieldIdx]);
    fieldIdx++;

    // - slotIndex
    this.slotIndex = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    // - operator
    this.operator = parseInt(sVals[fieldIdx]);
    fieldIdx++;

    //  - values
    for (let index = 0; index < this.getValueArrSize(); index++) {
      this.value.push(BigInt(sVals[fieldIdx]));
      fieldIdx++;
    }

    // - verifierID
    if (sVals[fieldIdx] !== '0') {
      this.verifierID = Id.fromBigInt(BigInt(sVals[fieldIdx]));
    }
    fieldIdx++;

    // - nullifierSessionID
    this.nullifierSessionID = BigInt(sVals[fieldIdx]);

    return this;
  }
}

const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

export class AtomicQueryV3PubSignalsVerifier
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  pubSignals = new AtomicQueryV3PubSignals();

  constructor(pubSignals: string[]) {
    super();
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals))
    );

    this.userId = this.pubSignals.userID;
    this.challenge = this.pubSignals.requestID;
  }

  async verifyQuery(
    query: ProofQuery,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts,
    params?: JSONObject
  ): Promise<BaseConfig> {
    const outs: ClaimOutputs = {
      issuerId: this.pubSignals.issuerID,
      schemaHash: this.pubSignals.claimSchema,
      slotIndex: this.pubSignals.slotIndex,
      operator: this.pubSignals.operator,
      value: this.pubSignals.value,
      timestamp: this.pubSignals.timestamp,
      merklized: this.pubSignals.merklized,
      claimPathKey: this.pubSignals.claimPathKey,
      claimPathNotExists: this.pubSignals.claimPathNotExists,
      valueArraySize: this.pubSignals.getValueArrSize(),
      isRevocationChecked: this.pubSignals.isRevocationChecked
    };
    await checkQueryRequest(query, outs, schemaLoader, verifiablePresentation, opts);

    const { proofType, verifierID, nullifier, nullifierSessionID, linkID } = this.pubSignals;

    switch (query.proofType) {
      case ProofType.BJJSignature:
        if (proofType !== 1) {
          throw new Error('wrong proof type for BJJSignature');
        }
        break;
      case ProofType.Iden3SparseMerkleTreeProof:
        if (proofType !== 2) {
          throw new Error('wrong proof type for Iden3SparseMerkleTreeProof');
        }
        break;
      default:
        throw new Error('invalid proof type');
    }

    const nullifierSessionIDparam = params?.nullifierSessionId;

    if (nullifierSessionIDparam) {
      if (nullifier && BigInt(nullifier) !== 0n) {
        // verify nullifier information
        const verifierDIDParam = params?.verifierDid;
        if (!verifierDIDParam) {
          throw new Error('verifierDid is required');
        }

        const id = DID.idFromDID(verifierDIDParam as DID);

        if (verifierID.bigInt() != id.bigInt()) {
          throw new Error('wrong verifier is used for nullification');
        }
        const nSessionId = BigInt(nullifierSessionIDparam as string);

        if (nullifierSessionID !== nSessionId) {
          throw new Error(
            `wrong verifier session id is used for nullification, expected ${nSessionId}, got ${nullifierSessionID}`
          );
        }
      }
    } else if (nullifierSessionID !== 0n) {
      throw new Error(`Nullifier id is generated but wasn't requested`);
    }

    if (!query.groupId && linkID !== 0n) {
      throw new Error(`proof contains link id, but group id is not provided`);
    }

    if (query.groupId && linkID === 0n) {
      throw new Error("proof doesn't contain link id, but group id is provided");
    }

    return this.pubSignals;
  }

  async verifyStates(resolvers: StateResolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.pubSignals.issuerID);
    if (!resolver) {
      throw new Error(`resolver not found for issuerID ${this.pubSignals.issuerID.string()}`);
    }

    await checkUserState(resolver, this.pubSignals.issuerID, this.pubSignals.issuerState);

    if (this.pubSignals.isRevocationChecked === 0) {
      return;
    }

    const issuerNonRevStateResolved = await checkIssuerNonRevState(
      resolver,
      this.pubSignals.issuerID,
      this.pubSignals.issuerClaimNonRevState
    );

    const acceptedStateTransitionDelay =
      opts?.acceptedStateTransitionDelay ?? defaultProofVerifyOpts;

    if (issuerNonRevStateResolved.latest) {
      return;
    }

    const timeDiff =
      Date.now() -
      getDateFromUnixTimestamp(Number(issuerNonRevStateResolved.transitionTimestamp)).getTime();
    if (timeDiff > acceptedStateTransitionDelay) {
      throw new Error('issuer state is outdated');
    }
  }
}
