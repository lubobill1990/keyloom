import { VaultService, type ServiceOptions } from "./service";
import { Updater } from "./updater";
import { rootFromResources } from "./platform";

export function createRuntime(options: ServiceOptions) {
  const service = new VaultService({ ...options, healthPending: !!(process.env.KEYLOOM_UPDATE_HEALTH || process.env.KEYLOOM_UPDATE_NONCE) });
  service.updater = new Updater({ root: rootFromResources(options.resources), resources: options.resources, state: service.state,
    vault: () => service.data, notify: state => options.notify?.({ event: "updateChanged", state }) });
  return service;
}
