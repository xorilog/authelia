import { useLongRunningTask } from "./RemoteCall";
import { getRequestedScopes } from "../services/Consent";

export function useRequestedScopes() {
    return useLongRunningTask(getRequestedScopes, []);
}