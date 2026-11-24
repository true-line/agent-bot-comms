// The agent-comms HQ plugin: exactly one default export (agent-bot-hq SDK,
// plan §4.1). Today it is broker mode (ADR-0306).
import { brokerPlugin } from './broker.mjs';

// The installed plugin exposes B-only qualification, relay ingress and completion routes
// only when HQ admission confirms their Machine-backed authorizers on the live
// v2 bridge binding. The relay payload stays opaque here; HQ owns its framing.
export default brokerPlugin({ enableBridgeQualification: true, enableBridgeRelayIngress: true,
  enableBridgeRelayPrewrite: true, enableBridgeRelayCompletion: true });
