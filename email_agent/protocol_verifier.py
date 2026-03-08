import spf
import dkim
import checkdmarc
from typing import Dict, Any, Optional

class ProtocolVerifier:
    def __init__(self):
        pass

    def verify_spf(self, ip: str, domain: str, sender: str) -> Dict[str, Any]:
        """
        Xác thực SPF cho email.
        :param ip: IP của mail server gửi
        :param domain: Tên miền (thường lấy từ HELO/EHLO hoặc từ email)
        :param sender: Địa chỉ email người gửi (Return-Path)
        """
        try:
            # spf.check2 trả về (result, code, explanation)
            result, code, explanation = spf.check2(i=ip, s=sender, h=domain)
            
            # Các kết quả SPF: pass, fail, softfail, neutral, none, permerror, temperror
            # temperror thường do DNS timeout
            return {
                "pass": result.lower() == "pass",
                "result": result.lower(),
                "detail": explanation,
                "error": None
            }
        except Exception as e:
            return {
                "pass": False,
                "result": "error",
                "detail": "Lỗi nội bộ khi kiểm tra SPF",
                "error": str(e)
            }

    def verify_dkim(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Xác thực DKIM dựa trên nội dung raw của email.
        :param raw_email: Nội dung email ở dạng bytes
        """
        try:
            # dkim.verify trả về True nếu chữ ký hợp lệ
            is_valid = dkim.verify(raw_email)
            return {
                "pass": is_valid,
                "result": "pass" if is_valid else "fail",
                "detail": "Chữ ký DKIM hợp lệ" if is_valid else "Chữ ký DKIM không hợp lệ hoặc bị thiếu",
                "error": None
            }
        except dkim.DKIMException as e:
            return {
                "pass": False,
                "result": "error",
                "detail": "Lỗi định dạng khi kiểm tra DKIM",
                "error": str(e)
            }
        except Exception as e:
            return {
                "pass": False,
                "result": "error",
                "detail": "Lỗi hệ thống khi kiểm tra DKIM",
                "error": str(e)
            }

    def verify_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Xác thực DMARC cho tên miền. 
        Note: checkdmarc sẽ thực hiện DNS lookup.
        :param domain: Tên miền gửi (thường lấy từ header From)
        """
        try:
            # checkdmarc parses DMARC records
            dmarc_info = checkdmarc.check_dmarc_record(domain)
            
            policy = dmarc_info.get("tags", {}).get("p", {}).get("value", "none")
            record = dmarc_info.get("record", "")
            
            return {
                "pass": True, # Nếu lấy được record dmarc hợp lệ thì pass check
                "result": "pass",
                "detail": f"DMARC policy: {policy}",
                "policy": policy,
                "record": record,
                "error": None
            }
        except checkdmarc.DMARCRecordNotFound as e:
            return {
                "pass": False,
                "result": "none",
                "detail": "Không tìm thấy bản ghi DMARC",
                "policy": "none",
                "record": "",
                "error": str(e)
            }
        except checkdmarc.DMARCRecordIncomplete as e:
            return {
                "pass": False,
                "result": "error",
                "detail": "Bản ghi DMARC không hoàn chỉnh",
                "policy": "none",
                "record": "",
                "error": str(e)
            }
        except checkdmarc.checkdmarcError as e:
            # Các lỗi khác của checkdmarc (ví dụ Timeout)
            return {
                "pass": False,
                "result": "error",
                "detail": "Lỗi khi kiểm tra DMARC (có thể do DNS Timeout)",
                "policy": "none",
                "record": "",
                "error": str(e)
            }
        except Exception as e:
            return {
                "pass": False,
                "result": "error",
                "detail": "Lỗi DNS timeout hoặc lỗi nội bộ khác khi kiểm tra DMARC",
                "policy": "none",
                "record": "",
                "error": str(e)
            }

    def verify_all(self, ip: str, sender_domain: str, sender_email: str, from_domain: str, raw_email: bytes) -> Dict[str, Any]:
        """
        Kiểm tra toàn bộ SPF, DKIM, DMARC.
        :param ip: IP người gửi (dùng cho SPF)
        :param sender_domain: Tên miền HELO/EHLO (dùng cho SPF)
        :param sender_email: Email người gửi thực sự ở Return-Path (dùng cho SPF)
        :param from_domain: Tên miền trong header From (dùng cho DMARC)
        :param raw_email: Nội dung nguyên bản của email (dùng cho DKIM)
        """
        spf_res = self.verify_spf(ip, sender_domain, sender_email)
        dkim_res = self.verify_dkim(raw_email)
        dmarc_res = self.verify_dmarc(from_domain)
        
        # Kiểm tra tính đồng nhất (Alignment) rất quan trọng trong DMARC
        # Nhưng ở bước đầu, chúng ta trả về dict tổng hợp trước.
        return {
            "spf": spf_res,
            "dkim": dkim_res,
            "dmarc": dmarc_res
        }
