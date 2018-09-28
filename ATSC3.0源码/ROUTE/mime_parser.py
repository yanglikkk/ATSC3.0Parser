import email.parser
import email.message
from email import policy

# 输入二进制读取MIME内容文件对象，解析MIME内容，存储XML文件
def parse(mime_file):
    mime_message = email.parser.Parser(policy=policy.default).parse(mime_file)
    mime_content_dict = {}
    if isinstance(mime_message, email.message.MIMEPart):
        for part in mime_message.iter_attachments():
            if isinstance(part, email.message.Message):
                # 构建文件名-文件内容键值对
                mime_content_dict[part.get('Content-Location')] = part.get_payload()
    else:
        print("error content of MIME")
    return mime_content_dict
