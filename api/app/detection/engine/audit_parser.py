import binascii

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
        Fallback parser if Data Prepper hasn't parsed the message yet.
        Very basic key=value extraction.
        """
        results = {}
        # Simple regex-less split for performance
        parts = message.split(' ')
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                # Remove quotes if present
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                results[k] = v
        return results

    @classmethod
    def normalize_log(cls, raw_log: dict) -> dict:
        """
        Enriches the raw log with decoded command line info.
        """
        # 1. If key_value didn't run, try to extract from message
        message = raw_log.get("message", "")
        extracted = cls.extract_fields(message)
        
        # 2. Decode any hex-encoded fields (proctitle, a0, a1, etc.)
        for k, v in extracted.items():
            if cls.is_hex(v):
                v = cls.decode_hex(v)
            raw_log[k] = v

        # Special handling for proctitle if it wasn't in extracted or needs re-decoding
        if "proctitle" in raw_log and cls.is_hex(raw_log["proctitle"]):
             raw_log["decoded_proctitle"] = cls.decode_hex(raw_log["proctitle"])
        
        # 3. Consolidate into command_line for the Rule Engine
        if raw_log.get("decoded_proctitle"):
            raw_log["command_line"] = raw_log["decoded_proctitle"]
        elif "a0" in raw_log:
            # Reconstruct from a0, a1, a2...
            args = []
            i = 0
            while f"a{i}" in raw_log:
                args.append(raw_log[f"a{i}"])
                i += 1
            raw_log["command_line"] = " ".join(args)
        elif raw_log.get("comm"):
             raw_log["command_line"] = raw_log["comm"]
             
        # 4. ECS Mapping (for YAMLDetectionEngine compatibility)
        if "process" not in raw_log:
            raw_log["process"] = {}
        
        # Map command line
        if raw_log.get("command_line"):
            raw_log["process"]["command_line"] = raw_log["command_line"]
        elif raw_log.get("cmdline"):
             raw_log["process"]["command_line"] = raw_log["cmdline"]
             
        # Map process name
        if raw_log.get("process_name"):
            raw_log["process"]["name"] = raw_log["process_name"]
        elif raw_log.get("comm"):
            raw_log["process"]["name"] = raw_log["comm"]
        elif raw_log.get("exe"):
             raw_log["process"]["name"] = raw_log["exe"].split("/")[-1]

        # Map user
        if "user" not in raw_log:
            raw_log["user"] = {}
        if raw_log.get("username"):
            raw_log["user"]["name"] = raw_log["username"]

        return raw_log
