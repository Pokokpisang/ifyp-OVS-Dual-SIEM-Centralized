import binascii

class AuditdParser:
    @staticmethod
    def decode_proctitle(hex_str: str) -> str:
        """
        Decodes a hex-encoded proctitle string from auditd.
        Replaces null bytes with spaces for readability.
        """
        if not hex_str:
            return ""
        try:
            # Strip potential auditd separators like \x1D
            clean_hex = hex_str.strip().replace('\x1d', '').replace('\x1D', '')
            # Ensure even length for unhexlify
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]
            decoded = binascii.unhexlify(clean_hex).decode('utf-8', errors='ignore')
            # proctitle often uses null bytes to separate args
            return decoded.replace('\x00', ' ').strip()
        except Exception:
            return hex_str

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
        extracted = cls.extract_fields(raw_log.get("message", ""))
        for k, v in extracted.items():
            if k not in raw_log:
                raw_log[k] = v

        # 2. Decode proctitle if present
        if "proctitle" in raw_log:
            raw_log["decoded_proctitle"] = cls.decode_proctitle(raw_log["proctitle"])
            print(f"[AuditParser] Decoded proctitle: {raw_log['decoded_proctitle']}", flush=True)
        
        # 3. Consolidate into command_line for the Rule Engine
        if raw_log.get("decoded_proctitle"):
            raw_log["command_line"] = raw_log["decoded_proctitle"]
        elif raw_log.get("comm"):
             raw_log["command_line"] = raw_log["comm"]
        elif raw_log.get("exe"):
             raw_log["command_line"] = raw_log["exe"]
             
        if raw_log.get("command_line"):
            print(f"[AuditParser] Normalized command_line: {raw_log['command_line']}", flush=True)
             
        return raw_log
