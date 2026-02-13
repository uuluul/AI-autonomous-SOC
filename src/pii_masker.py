import re

class PIIMasker:
    def __init__(self):
        self.patterns = {
            # Email
            'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            
            # Phone: 使用列表來支援多種不同格式
            'PHONE': [
                # 台灣手機: 09xx-xxx-xxx 或 09xxxxxxxx
                r'\b09\d{2}[- ]?\d{3}[- ]?\d{3}\b',
                
                # 國際格式: +886 9xx xxx xxx 或 +1-555-555-5555
                # 說明: +號開頭(選用) -> 國碼(1-3碼) -> 區碼/手機碼 -> 號碼
                r'\b(?:\+?\d{1,3}[- ]?)?\(?\d{1,4}\)?[- ]?\d{3,4}[- ]?\d{3,4}\b',
                
                # 純市話/美式: 555-123-4567 (為了補漏)
                r'\b\d{3}[-.]\d{3}[-.]\d{4}\b'
            ]
        }

    def mask(self, text):
        """將文字中的 PII 替換為 [TYPE]"""
        masked_text = text
        for pii_type, regex_list in self.patterns.items():
            # 判斷是單一字串還是列表
            if isinstance(regex_list, list):
                for pattern in regex_list:
                    masked_text = re.sub(pattern, f"[{pii_type}]", masked_text)
            else:
                masked_text = re.sub(regex_list, f"[{pii_type}]", masked_text)
        return masked_text

if __name__ == "__main__":
    # 地端測試各種格式
    masker = PIIMasker()
    test_str = """
    TW Mobile: 0912-345-678
    TW Mobile (No dash): 0912345678
    US Phone: 555-123-4567
    Intl Format: +886 912 345 678
    Date (Should NOT match): 2026-02-12
    IP (Should NOT match): 192.168.1.1
    """
    print(masker.mask(test_str))