import { AtomicQueryMTPV2PubSignalsVerifier } from './atomic-query-mtp-v2';
import { AtomicQuerySigV2PubSignalsVerifier } from './atomic-query-sig-v2';
import { AtomicQueryV3PubSignalsVerifier } from './atomic-query-v3';
import { AuthV2PubSignals } from './auth-v2';
import { LinkedMultiQueryVerifier } from './linked-multi-query';
import { PubSignals, PubSignalsVerifier } from './pub-signal-verifier';

const authV2 = AuthV2PubSignals;
const credentialAtomicQueryMTPV2 = AtomicQueryMTPV2PubSignalsVerifier;
const credentialAtomicQuerySigV2 = AtomicQuerySigV2PubSignalsVerifier;
const credentialAtomicQueryV3 = AtomicQueryV3PubSignalsVerifier;
const linkedMultiQuery10 = LinkedMultiQueryVerifier;

export type VerifierType = PubSignalsVerifier & PubSignals;

const supportedCircuits: { [key: string]: unknown } = {
  authV2,
  credentialAtomicQueryMTPV2,
  credentialAtomicQuerySigV2,
  credentialAtomicQueryV3,
  linkedMultiQuery10
};

export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    id = id.split('-')[0];
    return supportedCircuits[id] as VerifierType;
  }
}
