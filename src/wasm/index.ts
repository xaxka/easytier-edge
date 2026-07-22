import init from "./pkg/easytier_edge_wasm";
import wasmModule from "./pkg/easytier_edge_wasm_bg.wasm";

await init(wasmModule);

export * from "./pkg/easytier_edge_wasm";
