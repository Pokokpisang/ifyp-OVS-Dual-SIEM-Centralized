import binascii
import re

class AuditdParser:
    @staticmethod
    def is_hex(s: str) -> bool:
        """Checks if a string is likely a hex-encoded auditd string."""
        if not s or len(s) < 2 or len(s) % 2 != 0:
            return False
        # Auditd hex strings are usually uppercase or lowercase A-F, 0-9
        return all(c in "0123456789abcdefABCDEF" for c in s)

    @staticmethod
    def decode_hex(hex_str: str) -> str:
        """Decodes any hex-encoded string from auditd."""
        if not hex_str:
            return ""
        try:
            # Strip potential auditd separators
            clean_hex = hex_str.strip().replace('\x1d', '').replace('\x1D', '')
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]
            decoded = binascii.unhexlify(clean_hex).decode('utf-8', errors='ignore')
            # Replace null bytes with spaces (common in proctitle)
            return decoded.replace('\x00', ' ').strip()
        except Exception:
            return hex_str

    @staticmethod
    def decode_proctitle(hex_str: str) -> str:
        """Legacy helper for proctitle."""
        return AuditdParser.decode_hex(hex_str)

    @staticmethod
    def extract_fields(message: str) -> dict:
        """
        Extracts key=value pairs from auditd messages, handling quoted values with spaces.
        """
        # Regex to match key=value or key="value with spaces"
        pattern = r'([a-zA-Z0-9_]+)=(?:\"([^\"]*)\"|([^\s]+))'
        matches = re.findall(pattern, message)
        fields = {}
        for m in matches:
            key = m[0]
            # m[1] is the group inside quotes, m[2] is the group without quotes
            fields[key] = m[1] if m[1] else m[2]
        return fields

    @classmethod
    def normalize_log(cls, raw_log: dict) -> dict:
        """
        Enriches the raw log with decoded command line info and ECS mapping.
        """
        message = raw_log.get("message", "")
        log_type = raw_log.get("log_type", "")
        
        # 1. Base extraction
        extracted = cls.extract_fields(message)
        
        # 2. Decode hex-encoded fields selectively (avoid numeric fields like ppid, pid, uid)
        skip_hex_decode = {"ppid", "pid", "auid", "uid", "gid", "euid", "suid", "fsuid", "egid", "sgid", "fsgid", "ses", "exit", "items", "syscall"}
        for k, v in extracted.items():
            if k not in skip_hex_decode and cls.is_hex(v):
                v = cls.decode_hex(v)
            raw_log[k] = v

        # 3. ECS Mapping (for YAMLDetectionEngine compatibility)
        if "process" not in raw_log:
            raw_log["process"] = {}
        if "user" not in raw_log:
            raw_log["user"] = {}
        if "host" not in raw_log:
            raw_log["host"] = {}
        if "event" not in raw_log:
            raw_log["event"] = {}
        if "source" not in raw_log:
            raw_log["source"] = {}

        # Map host fields if they exist at root
        if "hostname" in raw_log:
            raw_log["host"]["name"] = raw_log["hostname"]
        elif "host" in raw_log and isinstance(raw_log["host"], str):
             raw_log["host"] = {"name": raw_log["host"]}
        
        if "ip_address" in raw_log:
            raw_log["host"]["ip"] = raw_log["ip_address"]

        # Map agent ID
        if "agent_id" in raw_log:
            if "agent" not in raw_log: raw_log["agent"] = {}
            raw_log["agent"]["id"] = raw_log["agent_id"]

        # 4. Handle auditd specific fields
        if "proctitle" in raw_log and cls.is_hex(raw_log["proctitle"]):
             raw_log["decoded_proctitle"] = cls.decode_hex(raw_log["proctitle"])
             raw_log["process"]["command_line"] = raw_log["decoded_proctitle"]
        
        elif "a0" in raw_log:
            args = []
            i = 0
            while f"a{i}" in raw_log:
                args.append(raw_log[f"a{i}"])
                i += 1
            raw_log["process"]["command_line"] = " ".join(args)
        
        if "comm" in raw_log:
            raw_log["process"]["name"] = raw_log["comm"]
        elif "exe" in raw_log:
            raw_log["process"]["name"] = raw_log["exe"].split("/")[-1]

        if "ppid" in raw_log:
            if "parent" not in raw_log["process"]: raw_log["process"]["parent"] = {}
            raw_log["process"]["parent"]["pid"] = int(raw_log["ppid"])
            # Note: parent name resolution is usually done via a stateful cache or system lookup
            # For now, we leave it empty unless provided by auditd (rare in SYSCALL)

        if "auid" in raw_log:
            raw_log["user"]["id"] = raw_log["auid"]
        if "username" in raw_log:
            raw_log["user"]["name"] = raw_log["username"]

        # 5. Handle SSH/Auth Specific Logs
        if log_type == "auth" or "sshd[" in message:
            raw_log["event"]["category"] = "authentication"
            raw_log["service"] = {"name": "ssh"}
            
            # Simple patterns for auth results
            if "Accepted password" in message or "session opened" in message:
                raw_log["auth"] = {"result": "success"}
                raw_log["event"]["outcome"] = "success"
            elif "Failed password" in message or "authentication failure" in message:
                raw_log["auth"] = {"result": "failure"}
                raw_log["event"]["outcome"] = "failure"
            
            # Extract IP from SSH logs (e.g., "from 192.168.1.100")
            ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if ip_match:
                raw_log["source"]["ip"] = ip_match.group(1)
            
            # Extract user
            user_match = re.search(r'for (invalid user )?(\w+)', message)
            if user_match:
                raw_log["user"]["name"] = user_match.group(2)

        return raw_log
