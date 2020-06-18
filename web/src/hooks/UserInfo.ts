import { getUserPreferences } from "../services/UserPreferences";
import { useLongRunningTask } from "./RemoteCall";

export function useUserPreferences() {
    return useLongRunningTask(getUserPreferences, []);
}