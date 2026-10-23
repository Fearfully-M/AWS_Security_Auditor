import json
from urllib.parse import quote

# decode = {"Statement": [{"Action": "s3:GetObject"},{"Action": "s3:PutObject"}]}

# json_string = json.dumps(decode)

# encode = quote(json_string)
# print(encode)

# items = []
# print(max(items))

policy_dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::my-bucket/*"]
        }
    ],
}

# Convert to a formatted JSON string
json_string = json.dumps(policy_dict, indent=4)
print(json_string)