import json
from urllib.parse import quote

decode = {"Statement": [{"Action": "s3:GetObject"},{"Action": "s3:PutObject"}]}

json_string = json.dumps(decode)

encode = quote(json_string)
print(encode)

items = []
print(max(items))