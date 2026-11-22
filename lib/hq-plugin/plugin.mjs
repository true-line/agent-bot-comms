// The agent-comms HQ plugin: exactly one default export (agent-bot-hq SDK,
// plan §4.1). Today it is broker mode (ADR-0306).
import { brokerPlugin } from './broker.mjs';

// The installed plugin exposes the qualification route only when HQ admission
// confirms its Machine-backed authorizer on the live B request.
export default brokerPlugin({ enableBridgeQualification: true });
