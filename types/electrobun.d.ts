// Project the shipped SDK contracts without checking its private FFI implementation.
import emitter from "../.sdk-types/bun/events/eventEmitter";
export { BrowserWindow } from "../.sdk-types/bun/core/BrowserWindow";
export { BrowserView } from "../.sdk-types/bun/core/BrowserView";
export * as Utils from "../.sdk-types/bun/core/Utils";
export * as PATHS from "../.sdk-types/bun/core/Paths";
export { Screen } from "../.sdk-types/bun/proc/native";
export type { ElectrobunConfig } from "../.sdk-types/bun/ElectrobunConfig";
export { default as ElectrobunEvent } from "../.sdk-types/bun/events/event";
declare const Electrobun: { events: typeof emitter };
export default Electrobun;
