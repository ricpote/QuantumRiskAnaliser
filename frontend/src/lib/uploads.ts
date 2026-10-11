export const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;
export const MAX_UPLOAD_FILES = 2000;
export const UPLOAD_HELP =
  "PCAP/PCAPNG, Python, Java, Go, JavaScript/TypeScript, AWS JSON, nginx/Apache/SSH/Terraform configuration, certificates and keys (PEM/DER/OpenSSH/PKCS#12), or ZIP. 32 MiB total.";
// Certificates and keys: parsed by the Python scanner (ingest/code/keys.py), DER and PKCS#12 are binary.
const KEY_EXTENSIONS = [
  "pem",
  "crt",
  "cer",
  "der",
  "cert",
  "csr",
  "req",
  "key",
  "pub",
  "p8",
  "pk8",
  "p12",
  "pfx",
];
const KEY_NAMES =
  /^(id_(rsa|dsa|ecdsa|ecdsa_sk|ed25519|ed25519_sk|xmss)(\.pub)?|ssh_host_\w+_key(\.pub)?|authorized_keys2?|known_hosts)$/;

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

// FileReader works in browsers that do not implement File.arrayBuffer().
export function readFile(file: Blob): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(new Error("This file could not be read. Select it again."));
    reader.onabort = () => reject(new Error("File reading was interrupted."));
    reader.readAsArrayBuffer(file);
  });
}

export async function validateFile(file: File): Promise<string | null> {
  if (!file.size) return "File is empty.";
  if (file.size > MAX_UPLOAD_BYTES) return "File exceeds the 32 MiB limit.";
  if (/[/\\:]/.test(file.name) || file.name.includes(String.fromCharCode(0)))
    return "Filename is not supported.";
  const bytes = new Uint8Array(await readFile(file.slice(0, 65536)));
  const magic = Array.from(bytes.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (
    ["py", "tf", "go", "java", "js", "mjs", "cjs", "jsx", "ts", "tsx"].includes(extension ?? "") &&
    !file.name.endsWith(`.${extension}`)
  )
    return `Use a lowercase .${extension} extension so the scanner recognizes this file.`;
  if (file.name.endsWith(".d.ts") || file.name.endsWith(".min.js"))
    return "The scanner skips type declarations and minified bundles. Select the original source.";
  if (extension === "zip")
    return ["504b0304", "504b0506", "504b0708"].includes(magic) ? null : "Not a valid ZIP header.";
  if (["pcap", "pcapng", "cap"].includes(extension ?? "")) {
    const classic =
      ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"].includes(magic) && file.size >= 24;
    const ng =
      magic === "0a0d0d0a" &&
      file.size >= 28 &&
      ["4d3c2b1a", "1a2b3c4d"].includes(
        Array.from(bytes.slice(8, 12))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(""),
      );
    return classic || ng ? null : "Not a valid PCAP/PCAPNG capture header.";
  }
  if (KEY_EXTENSIONS.includes(extension ?? "") || KEY_NAMES.test(file.name)) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes, {
      stream: file.size > bytes.length,
    });
  } catch {
    return "Expected a UTF-8 text file, not binary data.";
  }
  if (
    Array.from(text).some(
      (character) => character.charCodeAt(0) < 32 && !"\r\n\t\f".includes(character),
    )
  )
    return "Binary data cannot be scanned as source or configuration.";
  if (extension === "json") {
    try {
      const value: unknown = JSON.parse(new TextDecoder().decode(await readFile(file)));
      if (!value || typeof value !== "object" || Array.isArray(value))
        return "Choose an AWS KMS, ELB or ACM JSON export.";
      if (
        file.name === "package.json" ||
        ["Keys", "KeyMetadata", "LoadBalancers", "Listeners", "Certificates", "Certificate"].some(
          (k) => k in value,
        )
      )
        return null;
      return "JSON must be an AWS KMS, ELB or ACM export.";
    } catch {
      return "JSON could not be parsed.";
    }
  }
  if (
    ["py", "java", "go", "js", "mjs", "cjs", "jsx", "ts", "tsx"].includes(extension ?? "") ||
    ["requirements.txt", "go.mod", "pom.xml", "build.gradle"].includes(file.name)
  )
    return null;
  if (extension === "tf")
    return /^\s*(resource|data|variable|provider|terraform|locals|module|output)\b[^\n]*\{/m.test(
      text,
    )
      ? null
      : "Expected Terraform configuration blocks.";
  if (/sshd?_config/i.test(file.name)) return null;
  if (
    /^\s*(?:Host\b|Match\b|Port\b|HostKey\b|KexAlgorithms\b|Ciphers\b|MACs\b|PubkeyAcceptedAlgorithms\b|PasswordAuthentication\b|PermitRootLogin\b)/m.test(
      text,
    )
  )
    return null;
  if (
    extension === "conf" &&
    /\b(?:server\s*\{|ssl_|SSLEngine|SSLProtocol|SSLCipherSuite|VirtualHost)/i.test(text)
  )
    return null;
  if (text.includes("-----BEGIN ")) return null; // e.g. a YAML or .env file with an embedded PEM certificate
  return "Unsupported input. Choose a supported capture, source/config file, AWS export, certificate/key or ZIP.";
}
