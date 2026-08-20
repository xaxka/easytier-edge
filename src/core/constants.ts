export const EASYTIER_HEADER_SIZE = 16;
export const EASYTIER_AEAD_TAIL_SIZE = 28;
export const MAX_FORWARD_HOPS = 7;
export const SERVER_PEER_ID = 10_000_001;
export const WS_OPEN = 1;

export enum PacketType {
	Data = 1,
	Handshake = 2,
	Ping = 4,
	Pong = 5,
	RpcReq = 8,
	RpcResp = 9,
	NoiseHandshakeMsg1 = 13,
	NoiseHandshakeMsg3 = 15,
}

export const ENCRYPTED_FLAG = 0x01;
