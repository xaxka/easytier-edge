import { type EasyTierEnv, readServerConfig } from "./core/config";
import { errorMessage } from "./runtime/errors";

export { EasyTierServer } from "./server";

const DURABLE_OBJECT_NAME = "easytier-central-relay";

export default {
	async fetch(request: Request, env: EasyTierEnv): Promise<Response> {
		const url = new URL(request.url);
		if (url.pathname === "/healthz" && request.method === "GET") {
			try {
				const config = readServerConfig(env);
				return Response.json(
					{
						ok: true,
						secure_mode: true,
						disable_relay_data: config.disableRelayData,
					},
					{ headers: { "cache-control": "no-store" } },
				);
			} catch (error) {
				console.error("EasyTier configuration is invalid", {
					error: errorMessage(error),
				});
				return Response.json(
					{ ok: false, error: "invalid server configuration" },
					{ status: 503, headers: { "cache-control": "no-store" } },
				);
			}
		}

		if (url.pathname !== "/") return new Response("Not found", { status: 404 });
		if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
			return new Response("Expected a WebSocket upgrade", {
				status: 426,
				headers: { Upgrade: "websocket" },
			});
		}
		try {
			readServerConfig(env);
		} catch (error) {
			console.error("EasyTier configuration is invalid", {
				error: errorMessage(error),
			});
			return new Response("Server configuration is invalid", { status: 503 });
		}

		return env.EASYTIER_SERVER.getByName(DURABLE_OBJECT_NAME).fetch(request);
	},
} satisfies ExportedHandler<EasyTierEnv>;
