import { defineConfig } from "vitest/config";

const wasmModuleForNode = () => ({
	name: "wasm-module-for-node",
	enforce: "pre" as const,
	load(id: string): string | null {
		if (!id.endsWith(".wasm")) {
			return null;
		}

		return `import { readFileSync } from "node:fs";
export default new WebAssembly.Module(readFileSync(${JSON.stringify(id)}));`;
	},
});

export default defineConfig({
	plugins: [wasmModuleForNode()],
	test: {
		environment: "node",
	},
});
