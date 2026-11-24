// agent-secrets: gives each Claude Code session its own client's 1Password
// service account token, after one Touch ID approval per session.
//
// The client comes from clients.json, matched against the folder the calling
// Claude process was launched in. Approvals last as long as that Claude process.

import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

let home = NSHomeDirectory()
let configPath = home + "/.config/agent-secrets/clients.json"
let keychainService = "agent-secrets"
let approvalsDir = home + "/Library/Caches/agent-secrets"
let realOpCandidates = ["/opt/homebrew/bin/op", "/usr/local/bin/op"]

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data("agent-secrets: \(message)\n".utf8))
  exit(1)
}

// MARK: Process tree

struct Proc {
  let pid: pid_t
  let ppid: pid_t
  let name: String
  let startedAt: String
}

func cString<T>(_ tuple: T) -> String {
  withUnsafeBytes(of: tuple) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
}

func procInfo(_ pid: pid_t) -> Proc? {
  var info = kinfo_proc()
  var size = MemoryLayout<kinfo_proc>.stride
  var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
  guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
  let start = info.kp_proc.p_un.__p_starttime
  return Proc(
    pid: pid,
    ppid: info.kp_eproc.e_ppid,
    name: cString(info.kp_proc.p_comm),
    startedAt: "\(start.tv_sec).\(start.tv_usec)")
}

func workingFolder(_ pid: pid_t) -> String? {
  var vpi = proc_vnodepathinfo()
  let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
  guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, size) == size else { return nil }
  return cString(vpi.pvi_cdir.vip_path)
}

func executablePath(_ pid: pid_t) -> String? {
  var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
  guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
  return String(cString: buffer)
}

// The nearest ancestor running a Claude Code release binary.
func claudeSession() -> Proc? {
  let releases = home + "/.local/share/claude/versions/"
  var pid = getppid()
  while pid > 1, let proc = procInfo(pid) {
    if executablePath(pid)?.hasPrefix(releases) == true { return proc }
    pid = proc.ppid
  }
  return nil
}

// clients.json maps each client's key to its display name and folder:
// { "acme": { "name": "Acme Ltd", "folder": "~/code/acme" } }
struct Client: Decodable {
  var key = ""
  let name: String
  let folder: String
  enum CodingKeys: String, CodingKey { case name, folder }
}

func clients() -> [Client] {
  guard let data = FileManager.default.contents(atPath: configPath) else { return [] }
  guard let parsed = try? JSONDecoder().decode([String: Client].self, from: data) else {
    fail("couldn't read \(configPath)")
  }
  return parsed.map { key, client in
    var client = client
    client.key = key
    return client
  }
}

func expand(_ path: String) -> String {
  (NSString(string: path).expandingTildeInPath as NSString).standardizingPath
}

// The client whose folder is the longest match for the given folder.
func client(forFolder folder: String) -> Client? {
  clients()
    .filter { folder == expand($0.folder) || folder.hasPrefix(expand($0.folder) + "/") }
    .max { expand($0.folder).count < expand($1.folder).count }
}

func displayFolder(_ path: String) -> String {
  path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
}

// MARK: Keychain
// Items are created by this binary, so macOS trusts only this binary to read
// them silently. Any other program, including `security`, gets a dialog.

func tokenQuery(_ client: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: keychainService,
    kSecAttrAccount as String: client,
  ]
}

func readToken(_ client: String) -> String? {
  var query = tokenQuery(client)
  query[kSecReturnData as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  if status == errSecItemNotFound { return nil }
  guard status == errSecSuccess, let data = result as? Data, let token = String(data: data, encoding: .utf8)
  else { fail("couldn't read the \(client) token from Keychain (status \(status))") }
  return token
}

func storeToken(_ client: String, _ token: String) {
  SecItemDelete(tokenQuery(client) as CFDictionary)
  var item = tokenQuery(client)
  item[kSecAttrLabel as String] = "agent-secrets: \(client)"
  item[kSecValueData as String] = Data(token.utf8)
  let status = SecItemAdd(item as CFDictionary, nil)
  guard status == errSecSuccess else { fail("couldn't save to Keychain (status \(status))") }
}

// MARK: Approvals
// An approval file holds an HMAC of the session, keyed with the client's token.
// Only this binary can read the token, so nothing else can forge an approval.

func approvalPath(_ client: String, _ session: Proc) -> String {
  "\(approvalsDir)/\(client)-\(session.pid)-\(session.startedAt)"
}

func approvalTag(_ client: String, _ session: Proc, _ token: String) -> String {
  let message = Data("\(client)|\(session.pid)|\(session.startedAt)".utf8)
  let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: Data(token.utf8)))
  return mac.map { String(format: "%02x", $0) }.joined()
}

func isApproved(_ client: String, _ session: Proc, _ token: String) -> Bool {
  let saved = try? String(contentsOfFile: approvalPath(client, session), encoding: .utf8)
  return saved == approvalTag(client, session, token)
}

func askTouchID(_ reason: String) -> Bool {
  let context = LAContext()
  context.localizedFallbackTitle = ""
  let policy: LAPolicy =
    context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
  let done = DispatchSemaphore(value: 0)
  var allowed = false
  context.evaluatePolicy(policy, localizedReason: reason) { ok, _ in
    allowed = ok
    done.signal()
  }
  done.wait()
  return allowed
}

func removeStaleApprovals() {
  let files = (try? FileManager.default.contentsOfDirectory(atPath: approvalsDir)) ?? []
  for file in files {
    let parts = file.split(separator: "-")
    guard parts.count >= 3, let pid = pid_t(parts[parts.count - 2]) else { continue }
    if procInfo(pid)?.startedAt != String(parts[parts.count - 1]) {
      try? FileManager.default.removeItem(atPath: "\(approvalsDir)/\(file)")
    }
  }
}

func approve(_ client: Client, _ session: Proc, _ folder: String, _ token: String) {
  let reason = "let the Claude session in \(displayFolder(folder)) use the \(client.name) agent token"
  guard askTouchID(reason) else { fail("Touch ID approval for \(client.name) was declined") }
  let key = client.key
  removeStaleApprovals()
  try? FileManager.default.createDirectory(
    atPath: approvalsDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  let saved = FileManager.default.createFile(
    atPath: approvalPath(key, session), contents: Data(approvalTag(key, session, token).utf8),
    attributes: [.posixPermissions: 0o600])
  if !saved { fail("couldn't save the approval") }
}

// MARK: Commands

func execRealOp(_ args: [String]) -> Never {
  guard let op = realOpCandidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
  else { fail("couldn't find the 1Password CLI") }
  let argv = ([op] + args).map { strdup($0) } + [nil]
  execv(op, argv)
  fail("couldn't run \(op)")
}

// Runs the real `op`. Inside a client's Claude session with a stored token,
// it runs as that client's service account.
func runOp(_ args: [String]) -> Never {
  guard let session = claudeSession(), let folder = workingFolder(session.pid),
    let client = client(forFolder: folder), let token = readToken(client.key)
  else { execRealOp(args) }
  if !isApproved(client.key, session, token) { approve(client, session, folder, token) }
  setenv("OP_SERVICE_ACCOUNT_TOKEN", token, 1)
  execRealOp(args)
}

func store(_ client: String) {
  if claudeSession() != nil { fail("run this in your own terminal, not from Claude") }
  if isatty(STDIN_FILENO) != 0 {
    fail("pipe the token in, for example: pbpaste | agent-secrets store \(client)")
  }
  let token = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
    .trimmingCharacters(in: .whitespacesAndNewlines)
  guard token.hasPrefix("ops_") else { fail("that doesn't look like a service account token") }
  storeToken(client, token)
  print("Saved the \(client) token.")
}

func status() {
  guard let session = claudeSession() else { return print("Not inside a Claude session.") }
  let folder = workingFolder(session.pid) ?? "unknown"
  print("Claude session: pid \(session.pid), launched in \(displayFolder(folder))")
  guard let client = client(forFolder: folder) else { return print("Client: none") }
  let token = readToken(client.key)
  print("Client: \(client.name) (\(client.key))")
  print("Token stored: \(token != nil ? "yes" : "no")")
  print("Approved: \(token.map { isApproved(client.key, session, $0) ? "yes" : "no" } ?? "no")")
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "op": runOp(Array(args.dropFirst()))
case "store" where args.count == 2: store(args[1])
case "status": status()
default:
  fail("usage: agent-secrets op <op args> | agent-secrets store <client> | agent-secrets status")
}
