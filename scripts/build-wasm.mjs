import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path, { delimiter } from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "src", "wasm", "pkg");
const temporaryOutDir = path.join(root, ".tmp", "wasm-pkg");
const manifest = path.join(root, "wasm", "Cargo.toml");
const cargoExecutable = process.platform === "win32" ? "cargo.exe" : "cargo";
const rustupVersion = "1.29.0";
const rustupUrl = `https://static.rust-lang.org/rustup/archive/${rustupVersion}/x86_64-unknown-linux-gnu/rustup-init`;
const rustupSha256 =
	"4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10";

const run = (command, args, options) =>
	new Promise((resolve, reject) => {
		const child = spawn(command, args, options);
		child.once("error", reject);
		child.once("exit", (code) => resolve(code ?? 1));
	});

const commandSucceeds = async (command, args) => {
	try {
		return (await run(command, args, { stdio: "ignore" })) === 0;
	} catch (error) {
		if (error instanceof Error && "code" in error && error.code === "ENOENT") {
			return false;
		}
		throw error;
	}
};

const downloadRustup = async (destination) => {
	let lastError;
	for (let attempt = 1; attempt <= 3; attempt += 1) {
		try {
			const response = await fetch(rustupUrl, {
				signal: AbortSignal.timeout(30_000),
			});
			if (!response.ok) {
				throw new Error(
					`rustup download failed with HTTP status ${response.status}`,
				);
			}

			const bytes = Buffer.from(await response.arrayBuffer());
			const sha256 = createHash("sha256").update(bytes).digest("hex");
			if (sha256 !== rustupSha256) {
				throw new Error(
					`rustup checksum mismatch: expected ${rustupSha256}, received ${sha256}`,
				);
			}

			await writeFile(destination, bytes, { mode: 0o700 });
			await chmod(destination, 0o700);
			return;
		} catch (error) {
			lastError = error;
			if (attempt < 3) {
				console.warn("rustup download failed; retrying", { attempt, error });
			}
		}
	}

	throw new Error("failed to download the verified rustup installer", {
		cause: lastError,
	});
};

const prepareBuildEnvironment = async () => {
	if (await commandSucceeds(cargoExecutable, ["--version"])) {
		return process.env;
	}
	if (process.env.WORKERS_CI !== "1") {
		throw new Error(
			"cargo was not found; install the Rust toolchain declared in rust-toolchain.toml",
		);
	}
	if (process.platform !== "linux" || process.arch !== "x64") {
		throw new Error(
			`automatic Rust installation is unsupported on ${process.platform}/${process.arch}`,
		);
	}

	const cargoHome = process.env.CARGO_HOME ?? path.join(homedir(), ".cargo");
	const rustupHome = process.env.RUSTUP_HOME ?? path.join(homedir(), ".rustup");
	const buildEnvironment = {
		...process.env,
		CARGO_HOME: cargoHome,
		RUSTUP_HOME: rustupHome,
		PATH: `${path.join(cargoHome, "bin")}${delimiter}${process.env.PATH ?? ""}`,
	};
	const installer = path.join(tmpdir(), `rustup-init-${process.pid}`);
	const rustupExecutable = path.join(cargoHome, "bin", "rustup");

	try {
		await downloadRustup(installer);
		const installExitCode = await run(
			installer,
			[
				"-y",
				"--profile",
				"minimal",
				"--default-toolchain",
				"none",
				"--no-modify-path",
			],
			{ cwd: root, env: buildEnvironment, stdio: "inherit" },
		);
		if (installExitCode !== 0) {
			throw new Error(`rustup-init exited with status ${installExitCode}`);
		}

		const toolchainExitCode = await run(rustupExecutable, ["toolchain", "install"], {
			cwd: root,
			env: buildEnvironment,
			stdio: "inherit",
		});
		if (toolchainExitCode !== 0) {
			throw new Error(
				`rustup toolchain install exited with status ${toolchainExitCode}`,
			);
		}
	} finally {
		await rm(installer, { force: true });
	}

	return buildEnvironment;
};

await access(manifest);
const buildEnvironment = await prepareBuildEnvironment();
await rm(temporaryOutDir, { recursive: true, force: true });
await mkdir(temporaryOutDir, { recursive: true });

const executable = process.platform === "win32" ? "wasm-pack.cmd" : "wasm-pack";
let exitCode;
try {
	exitCode = await run(
		executable,
		[
			"build",
			path.join(root, "wasm"),
			"--release",
			"--target",
			"web",
			"--out-dir",
			temporaryOutDir,
			"--out-name",
			"easytier_edge_wasm",
			"--locked",
		],
		{
			cwd: root,
			stdio: "inherit",
			shell: process.platform === "win32",
			env: buildEnvironment,
		},
	);
} catch (error) {
	await rm(temporaryOutDir, { recursive: true, force: true });
	throw error;
}

if (exitCode !== 0) {
	await rm(temporaryOutDir, { recursive: true, force: true });
	throw new Error(`wasm-pack exited with status ${exitCode}`);
}

await rm(outDir, { recursive: true, force: true });
await rename(temporaryOutDir, outDir);
await writeFile(path.join(outDir, ".gitkeep"), "");
