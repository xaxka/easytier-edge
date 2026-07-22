import { type Connection } from "./connection";

export class RoomRegistry {
	private readonly rooms = new Map<string, Map<number, Connection>>();

	get(networkName: string, peerId: number): Connection | undefined {
		return this.rooms.get(networkName)?.get(peerId);
	}

	set(connection: Connection): Connection | undefined {
		let room = this.rooms.get(connection.networkName);
		if (room === undefined) {
			room = new Map<number, Connection>();
			this.rooms.set(connection.networkName, room);
		}
		const previous = room.get(connection.peerId);
		room.set(connection.peerId, connection);
		return previous;
	}

	delete(connection: Connection): boolean {
		const room = this.rooms.get(connection.networkName);
		if (room?.get(connection.peerId) !== connection) return false;
		room.delete(connection.peerId);
		if (room.size === 0) this.rooms.delete(connection.networkName);
		return true;
	}

	peers(networkName: string): Iterable<Connection> {
		return this.rooms.get(networkName)?.values() ?? [];
	}
}
