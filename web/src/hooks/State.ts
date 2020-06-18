import { getState } from "../services/State";
import { useLongRunningTask } from "./RemoteCall";

export function useAutheliaState() {
    return useLongRunningTask(getState, []);
}