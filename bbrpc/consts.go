package bbrpc

// GRPCMaxMsgSize bounds the maximum gRPC message size for peer-to-peer RPCs.
// This small limit (16 KiB) helps mitigate DoS via oversized messages.
// Adjust with care if larger payloads are required.
const GRPCMaxMsgSize = 16 * 1024
