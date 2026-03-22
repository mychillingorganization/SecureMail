import ipaddress
import logging
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import checkdmarc
except ModuleNotFoundError:
    checkdmarc = None

try:
    from checkdmarc import dmarc as checkdmarc_dmarc
except (ModuleNotFoundError, ImportError):
    checkdmarc_dmarc = None

try:
    import dkim
except ModuleNotFoundError:
    dkim = None

try:
    import spf
except ModuleNotFoundError:
    spf = None


if dkim is not None:
    DKIMExceptionType = dkim.DKIMException
else:
    class DKIMExceptionType(Exception):
        pass


class DMARCRecordNotFoundType(Exception):
    pass


class DMARCRecordIncompleteType(Exception):
    pass


class DMARCErrorType(Exception):
    pass


if checkdmarc is not None or checkdmarc_dmarc is not None:
    DMARCRecordNotFoundType = getattr(checkdmarc, "DMARCRecordNotFound", getattr(checkdmarc_dmarc, "DMARCRecordNotFound", DMARCRecordNotFoundType))
    DMARCRecordIncompleteType = getattr(
        checkdmarc,
        "DMARCRecordIncomplete",
        getattr(checkdmarc_dmarc, "DMARCSyntaxError", DMARCRecordIncompleteType),
    )
    DMARCErrorType = getattr(checkdmarc, "checkdmarcError", getattr(checkdmarc_dmarc, "DMARCError", DMARCErrorType))


class ProtocolVerifier:
    def __init__(self):
        pass

    def _extract_domain_from_address(self, address: str | None) -> str | None:
        if not address:
            return None

        _, parsed_address = parseaddr(address)
        if "@" not in parsed_address:
            return None
        return parsed_address.rsplit("@", 1)[1].strip().lower()

    def _extract_public_ip(self, received_headers: list[str]) -> str | None:
        """Extract the first public IP from Received headers. Supports IPv4 and IPv6."""
        for header in received_headers:
            # Try IPv4 pattern: [x.x.x.x]
            ipv4_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", header)
            if ipv4_match:
                candidate = ipv4_match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if ip_obj.is_global:
                        logger.debug(f"Found public IPv4: {candidate}")
                        return candidate
                except ValueError:
                    pass

            # Fallback: search for bare IPv4 pattern
            for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header):
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if ip_obj.is_global and not candidate.endswith(".0"):  # Skip subnet addresses
                        logger.debug(f"Found public IPv4 (bare): {candidate}")
                        return candidate
                except ValueError:
                    pass

            # Try IPv6 pattern: [IPv6:...]
            ipv6_match = re.search(r"\[IPv6:([a-f0-9:]+)\]", header, re.IGNORECASE)
            if ipv6_match:
                candidate = ipv6_match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if ip_obj.is_global:
                        logger.debug(f"Found public IPv6: {candidate}")
                        return candidate
                except ValueError:
                    pass

        logger.warning("No public IP found in Received headers")
        return None

    def _extract_helo_domain(self, received_headers: list[str]) -> str | None:
        """Extract HELO domain from Received headers. Tries multiple patterns."""
        for header in received_headers:
            # Pattern 1: "from domain.com" or "from [IP.IP.IP.IP] (domain.com)"
            match = re.search(r"\bfrom\s+([^\s(\[]+)", header, re.IGNORECASE)
            if match:
                candidate = match.group(1).rstrip(".").lower()
                if candidate != "unknown_domain" and "." in candidate and not re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                    logger.debug(f"Found HELO domain (from pattern): {candidate}")
                    return candidate

            # Pattern 2: "by domain.com" - sometimes appears in Received headers
            match = re.search(r"\sby\s+([^\s.\[\]]+\.[^\s\[\]]+)", header, re.IGNORECASE)
            if match:
                candidate = match.group(1).rstrip(".").lower()
                if candidate != "unknown_domain" and "." in candidate:
                    logger.debug(f"Found HELO domain (by pattern): {candidate}")
                    return candidate

        logger.warning("No HELO domain found in Received headers")
        return None

    def _load_eml_context(self, file_path: str | Path) -> dict[str, Any]:
        """
        Extract email context from .eml file for protocol verification.
        Returns extracted IP, sender domain, sender email, From domain, and raw email bytes.
        Raises ValueError if critical data cannot be extracted.
        """
        eml_path = Path(file_path).expanduser().resolve()
        if not eml_path.exists() or not eml_path.is_file():
            raise FileNotFoundError(f"Không tìm thấy file .eml: {eml_path}")
        if eml_path.suffix.lower() != ".eml":
            raise ValueError(f"File đầu vào phải là .eml: {eml_path}")

        logger.info(f"Loading .eml file: {eml_path}")
        raw_email = eml_path.read_bytes()

        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
        except Exception as e:
            raise ValueError(f"Không thể phân tích file .eml ({type(e).__name__}): {e}")

        received_headers = message.get_all("Received", [])
        if not received_headers:
            logger.warning("No 'Received' headers found in email")
            received_headers = []

        # Extract sender email: try Return-Path first, then From
        return_path = message.get("Return-Path", "")
        from_header = message.get("From", "")
        sender_email = parseaddr(return_path)[1] if return_path else parseaddr(from_header)[1]
        if not sender_email:
            logger.warning(f"Could not extract sender email. Return-Path={return_path!r}, From={from_header!r}")

        # Extract From email
        from_email = parseaddr(from_header)[1] if from_header else ""
        if not from_email:
            logger.warning(f"Could not extract From email")

        # Extract domains
        sender_domain = self._extract_helo_domain(received_headers) or self._extract_domain_from_address(sender_email)
        from_domain = self._extract_domain_from_address(from_email)

        # Extract sender IP
        ip = self._extract_public_ip(received_headers)

        # Check for critical missing fields and provide detailed feedback
        missing_fields = []
        if not ip:
            missing_fields.append("IP công cộng từ headers Received")
        if not sender_domain:
            missing_fields.append("tên miền người gửi")
        if not sender_email:
            missing_fields.append("email người gửi (Return-Path hoặc From)")
        if not from_domain:
            missing_fields.append("tên miền From")

        if missing_fields:
            error_msg = f"Thiếu dữ liệu để xác thực thực tế:\n" + "\n".join(f"  - {f}" for f in missing_fields)
            logger.error(error_msg)
            logger.error(f"  Return-Path: {return_path}")
            logger.error(f"  From: {from_header}")
            logger.error(f"  Received headers (count): {len(received_headers)}")
            if received_headers:
                logger.debug(f"  First Received header: {received_headers[0][:200]}")
            raise ValueError(error_msg)

        logger.info(
            f"Successfully extracted email context:\n"
            f"  IP: {ip}\n"
            f"  Sender Domain: {sender_domain}\n"
            f"  Sender Email: {sender_email}\n"
            f"  From Domain: {from_domain}"
        )

        return {
            "ip": ip,
            "sender_domain": sender_domain,
            "sender_email": sender_email,
            "from_domain": from_domain,
            "raw_email": raw_email,
        }

    def _parse_eml_message(self, file_path: str | Path) -> tuple[Path, bytes, EmailMessage]:
        """Read and parse an EML file once for both live and header-based verification."""
        eml_path = Path(file_path).expanduser().resolve()
        if not eml_path.exists() or not eml_path.is_file():
            raise FileNotFoundError(f"Không tìm thấy file .eml: {eml_path}")
        if eml_path.suffix.lower() != ".eml":
            raise ValueError(f"File đầu vào phải là .eml: {eml_path}")

        raw_email = eml_path.read_bytes()
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
        except Exception as e:
            raise ValueError(f"Không thể phân tích file .eml ({type(e).__name__}): {e}")

        return eml_path, raw_email, message

    def _header_protocol_result(self, protocol_name: str, auth_headers: list[str], received_spf_headers: list[str]) -> dict[str, Any] | None:
        """Extract SPF/DKIM/DMARC status from Authentication-Results style headers."""
        pattern = re.compile(
            rf"\b{protocol_name}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            re.IGNORECASE,
        )
        status: str | None = None
        source = "authentication-results"

        for header in auth_headers:
            match = pattern.search(header)
            if match:
                status = match.group(1).lower()
                source = "authentication-results"
                break

        if protocol_name == "spf" and status is None:
            for header in received_spf_headers:
                match = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", header, re.IGNORECASE)
                if match:
                    status = match.group(1).lower()
                    source = "received-spf"
                    break

        if status is None:
            return None

        return {
            "pass": status == "pass",
            "result": status,
            "detail": f"Kết quả lấy từ header ({source})",
            "error": None,
        }

    def _extract_header_auth_fallback(self, message: EmailMessage) -> dict[str, Any] | None:
        """Build fallback SPF/DKIM/DMARC result from trusted authentication headers."""
        auth_headers = [h for h in (message.get_all("Authentication-Results", []) + message.get_all("ARC-Authentication-Results", [])) if h]
        received_spf_headers = [h for h in message.get_all("Received-SPF", []) if h]

        spf_res = self._header_protocol_result("spf", auth_headers, received_spf_headers)
        dkim_res = self._header_protocol_result("dkim", auth_headers, received_spf_headers)
        dmarc_res = self._header_protocol_result("dmarc", auth_headers, received_spf_headers)

        if not any([spf_res, dkim_res, dmarc_res]):
            return None

        return {
            "spf": spf_res,
            "dkim": dkim_res,
            "dmarc": dmarc_res,
        }

    def _merge_live_with_header_fallback(self, live_result: dict[str, Any], header_result: dict[str, Any] | None) -> dict[str, Any]:
        """Prefer live verification, but use header fallback when live checks are not trustworthy."""
        if not header_result:
            return live_result

        merged = {
            "spf": dict(live_result.get("spf", {})),
            "dkim": dict(live_result.get("dkim", {})),
            "dmarc": dict(live_result.get("dmarc", {})),
        }

        for key in ("spf", "dkim", "dmarc"):
            fallback = header_result.get(key)
            if not fallback:
                continue

            current = merged.get(key, {})
            current_result = str(current.get("result", "")).lower()
            should_replace = current_result in {"", "error", "fail", "softfail", "neutral", "none", "temperror", "permerror"}

            if should_replace:
                merged[key] = fallback

        return merged

    def verify_spf(self, ip: str | None = None, domain: str | None = None, sender: str | None = None) -> dict[str, Any]:
        """
        Xác thực SPF cho email.
        :param ip: IP của mail server gửi
        :param domain: Tên miền (thường lấy từ HELO/EHLO hoặc từ email)
        :param sender: Địa chỉ email người gửi (Return-Path)
        """
        try:
            if not ip or not domain or not sender:
                return {"pass": False, "result": "error", "detail": "Thiếu dữ liệu để kiểm tra SPF", "error": "ip, domain, sender are required"}
            if spf is None:
                return {"pass": False, "result": "error", "detail": "Thiếu thư viện SPF để kiểm tra DNS trực tiếp", "error": "Missing dependency: spf"}

            spf_response = spf.check2(i=ip, s=sender, h=domain)
            if isinstance(spf_response, tuple):
                if len(spf_response) == 3:
                    result, _code, explanation = spf_response
                elif len(spf_response) == 2:
                    result, explanation = spf_response
                else:
                    raise ValueError(f"Unexpected SPF response shape: {spf_response!r}")
            else:
                raise ValueError(f"Unexpected SPF response type: {type(spf_response).__name__}")

            # Các kết quả SPF: pass, fail, softfail, neutral, none, permerror, temperror
            # temperror thường do DNS timeout
            return {"pass": result.lower() == "pass", "result": result.lower(), "detail": explanation, "error": None}
        except Exception as e:
            return {"pass": False, "result": "error", "detail": "Lỗi nội bộ khi kiểm tra SPF", "error": str(e)}

    def verify_dkim(self, raw_email: bytes | None = None) -> dict[str, Any]:
        """
        Xác thực DKIM dựa trên nội dung raw của email.
        Lưu ý: dkim.verify() sẽ thực hiện DNS lookup để lấy public key.
        Nếu DNS lookup thất bại hoặc signature hết hạn, sẽ return False.
        :param raw_email: Nội dung email ở dạng bytes
        """
        try:
            if raw_email is None:
                return {"pass": False, "result": "error", "detail": "Thiếu raw email để kiểm tra DKIM", "error": "raw_email is required"}
            if dkim is None:
                return {"pass": False, "result": "error", "detail": "Thiếu thư viện DKIM để kiểm tra raw email trực tiếp", "error": "Missing dependency: dkim"}

            # dkim.verify trả về True nếu chữ ký hợp lệ
            # Có thể raise exception nếu DNS timeout hoặc format error
            is_valid = dkim.verify(raw_email)
            
            if is_valid:
                logger.debug("DKIM signature verification successful")
                return {"pass": True, "result": "pass", "detail": "Chữ ký DKIM hợp lệ", "error": None}
            else:
                logger.debug("DKIM signature verification returned False (likely no signature, DNS lookup failed, or signature invalid)")
                return {"pass": False, "result": "fail", "detail": "Chữ ký DKIM không hợp lệ hoặc không thể xác thực (DNS lookup thất bại, hết hạn, hoặc không có chữ ký)", "error": None}
                
        except DKIMExceptionType as e:
            logger.debug(f"DKIM exception during verification: {type(e).__name__}: {e}")
            return {"pass": False, "result": "error", "detail": f"Lỗi định dạng khi kiểm tra DKIM: {type(e).__name__}", "error": str(e)}
        except Exception as e:
            logger.debug(f"Unexpected error during DKIM verification: {type(e).__name__}: {e}")
            return {"pass": False, "result": "error", "detail": f"Lỗi hệ thống khi kiểm tra DKIM: {type(e).__name__}", "error": str(e)}

    def verify_dmarc(self, domain: str | None = None) -> dict[str, Any]:
        """
        Xác thực DMARC cho tên miền.
        Note: checkdmarc sẽ thực hiện DNS lookup.
        :param domain: Tên miền gửi (thường lấy từ header From)
        """
        try:
            if not domain:
                return {"pass": False, "result": "error", "detail": "Thiếu domain để kiểm tra DMARC", "policy": "none", "record": "", "error": "domain is required"}
            if checkdmarc is None:
                return {"pass": False, "result": "error", "detail": "Thiếu thư viện DMARC để kiểm tra DNS trực tiếp", "policy": "none", "record": "", "error": "Missing dependency: checkdmarc"}

            dmarc_module = checkdmarc_dmarc or checkdmarc
            if dmarc_module is None or not hasattr(dmarc_module, "check_dmarc"):
                return {"pass": False, "result": "error", "detail": "Thiếu hàm check_dmarc để kiểm tra DMARC trực tiếp", "policy": "none", "record": "", "error": "Missing function: check_dmarc"}

            # checkdmarc.dmarc.check_dmarc parses DMARC records
            dmarc_info = dmarc_module.check_dmarc(domain)

            policy = dmarc_info.get("tags", {}).get("p", {}).get("value", "none")
            record = dmarc_info.get("record", "")

            return {
                "pass": True,  # Nếu lấy được record dmarc hợp lệ thì pass check
                "result": "pass",
                "detail": f"DMARC policy: {policy}",
                "policy": policy,
                "record": record,
                "error": None,
            }
        except DMARCRecordNotFoundType as e:
            return {"pass": False, "result": "none", "detail": "Không tìm thấy bản ghi DMARC", "policy": "none", "record": "", "error": str(e)}
        except DMARCRecordIncompleteType as e:
            return {"pass": False, "result": "error", "detail": "Bản ghi DMARC không hoàn chỉnh", "policy": "none", "record": "", "error": str(e)}
        except DMARCErrorType as e:
            # Các lỗi khác của checkdmarc (ví dụ Timeout)
            return {"pass": False, "result": "error", "detail": "Lỗi khi kiểm tra DMARC (có thể do DNS Timeout)", "policy": "none", "record": "", "error": str(e)}
        except Exception as e:
            return {"pass": False, "result": "error", "detail": "Lỗi DNS timeout hoặc lỗi nội bộ khác khi kiểm tra DMARC", "policy": "none", "record": "", "error": str(e)}

    def verify_all(
        self,
        ip: str | None = None,
        sender_domain: str | None = None,
        sender_email: str | None = None,
        from_domain: str | None = None,
        raw_email: bytes | None = None,
    ) -> dict[str, Any]:
        """
        Kiểm tra toàn bộ SPF, DKIM, DMARC.
        :param ip: IP người gửi (dùng cho SPF)
        :param sender_domain: Tên miền HELO/EHLO (dùng cho SPF)
        :param sender_email: Email người gửi thực sự ở Return-Path (dùng cho SPF)
        :param from_domain: Tên miền trong header From (dùng cho DMARC)
        :param raw_email: Nội dung nguyên bản của email (dùng cho DKIM)
        """
        logger.info("Starting protocol verification...")
        logger.debug(f"Parameters: ip={ip}, sender_domain={sender_domain}, sender_email={sender_email}, from_domain={from_domain}, raw_email_size={len(raw_email) if raw_email else 0}")

        spf_res = self.verify_spf(ip, sender_domain, sender_email)
        logger.info(f"SPF result: {spf_res['result']}")

        dkim_res = self.verify_dkim(raw_email)
        logger.info(f"DKIM result: {dkim_res['result']}")

        dmarc_res = self.verify_dmarc(from_domain)
        logger.info(f"DMARC result: {dmarc_res['result']}")

        return {"spf": spf_res, "dkim": dkim_res, "dmarc": dmarc_res}

    def verify_from_auth_headers(self, _auth_headers: Any) -> dict[str, Any]:
        raise ValueError("Không hỗ trợ xác thực từ auth_headers. Hãy dùng file .eml để kiểm tra thực tế.")

    def verify_from_auth_headers_file(self, _file_path: str | Path) -> dict[str, Any]:
        raise ValueError("Không hỗ trợ xác thực từ auth_headers.json. Hãy dùng file .eml để kiểm tra thực tế.")

    def verify_from_eml_file(self, file_path: str | Path) -> dict[str, Any]:
        """
        Main entry point: Load .eml file and perform full protocol verification.
        """
        logger.info(f"Starting verification from .eml file: {file_path}")
        eml_path, raw_email, message = self._parse_eml_message(file_path)
        header_fallback = self._extract_header_auth_fallback(message)

        try:
            context = self._load_eml_context(eml_path)
            live_result = self.verify_all(
                ip=context["ip"],
                sender_domain=context["sender_domain"],
                sender_email=context["sender_email"],
                from_domain=context["from_domain"],
                raw_email=context["raw_email"],
            )
            result = self._merge_live_with_header_fallback(live_result, header_fallback)
            logger.info("Verification completed successfully")
            return result
        except Exception as e:
            logger.warning(f"Live protocol verification failed, fallback to headers: {type(e).__name__}: {e}")
            if header_fallback:
                # Ensure all three keys exist for downstream orchestrator logic.
                return {
                    "spf": header_fallback.get("spf") or {"pass": False, "result": "error", "detail": "Không có SPF trong header", "error": "Missing SPF header"},
                    "dkim": header_fallback.get("dkim") or {"pass": False, "result": "error", "detail": "Không có DKIM trong header", "error": "Missing DKIM header"},
                    "dmarc": header_fallback.get("dmarc") or {
                        "pass": False,
                        "result": "error",
                        "detail": "Không có DMARC trong header",
                        "policy": "none",
                        "record": "",
                        "error": "Missing DMARC header",
                    },
                }

            logger.error(f"Verification failed: {type(e).__name__}: {e}")
            # Last resort to keep pipeline alive with explicit error payload.
            return {
                "spf": {"pass": False, "result": "error", "detail": "Lỗi khi kiểm tra SPF", "error": str(e)},
                "dkim": {"pass": False, "result": "error", "detail": "Lỗi khi kiểm tra DKIM", "error": str(e)},
                "dmarc": {
                    "pass": False,
                    "result": "error",
                    "detail": "Lỗi khi kiểm tra DMARC",
                    "policy": "none",
                    "record": "",
                    "error": str(e),
                },
            }
