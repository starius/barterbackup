BarterBackup – Agent Notes

Scope

- This file guides agents working in this repository.
- It documents terminology, API decisions, style rules, and open issues.

Terminology

- File: A user‑provided input. The client can submit one or more files.
- Content: A single finalized encrypted blob derived from the current set of
  files. This is what gets backed up to peers.

Client API (clirpc)

- RPCs use file‑centric operations:
  - SetFile(SetFileRequest) returns (SetFileResponse).
  - GetFile(GetFileRequest) returns (GetFileResponse).
  - ListFiles(ListFilesRequest) returns (ListFilesResponse) and returns only
    names.
- Messages:
  - File { string name; bytes data; }.
  - ListFilesResponse returns `repeated string name`.
- Older SetContent/SetFiles and GetContent/GetFiles were replaced by the above
  to clarify “file” vs “content”.

Stored metadata (storedpb)

- ContentRevision refers to versions produced by SetFile.
- Metadata fields use content‑focused names:
  - content_length (was userdata_length).
  - content_sha256 (was userdata_sha256).

Server API (bbrpc)

- Peer discovery, content revision sync, downloads, and chat remain as in the
  proto for now.
- ChatRequest oneof tags are fixed: msg = 3, file = 4, stop = 5.

Proto style rules

- Comments are English sentences: start with a capital letter and end with a
  period (or appropriate punctuation).
- Wrap lines at about 80 characters. If tabs are used, consider them as 8
  spaces for wrapping. Prefer spaces in comments.
- Field comments must start with the field name followed by a sentence, e.g.,
  "encrypted_chat_request is AEAD(ChatRequest)." and "name is ...".
- Always separate fields in messages with a single empty line for readability.

Next steps for contributors

- Regenerate Go stubs after .proto changes.
- Update daemon and CLI implementations to the new SetFile/GetFile/ListFiles
  API.
- Define missing message schemas referenced by comments:
  - ProposeContract*, CheckContract*, RecoverContent*.
  - ChatAction/ChatEvent in clirpc.
- No action needed for ChatRequest tags; they are already fixed.

RPC generation

- Use Docker for reproducible proto builds; do not install protoc or plugins
  on the host.
- Generate stubs: `make rpc`.
- protoc comes from Debian bookworm. Go plugins are pinned by Go 1.23 `tool`
  directives in `go.mod` and installed in the Docker image via `go install`.
- Subsequent runs only execute protoc; tools are preinstalled in the image.
- Commit generated `.pb.go` files.
