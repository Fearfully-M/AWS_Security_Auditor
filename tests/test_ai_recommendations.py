from add_ai_recommendations import add_ai_recommendations

class FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text

class FakeMessage:
    def __init__(self, text):
        self.content = [FakeTextBlock(text)]


class FakeMessages:
    def __init__(self, response_text):
        self.response_text = response_text

    def create(self, **kwargs):
        return FakeMessage(self.response_text)


class FakeAIClient:
    def __init__(self, response_text):
        self.messages = FakeMessages(response_text)



def test_ai_recommendations_adds_recommendation():
    findings = [
        {
            "domain": "SecurityGroup",
            "resource_id": "sg-123",
            "severity": "High",
            "threat_type": "Public SSH Exposure",
            "explanation": "Port 22 is exposed to 0.0.0.0/0",
            "recommendation": "",
        }
    ]

    fake_client = FakeAIClient(
        "Restrict SSH access to trusted IP ranges."
    )

    result = add_ai_recommendations(findings, fake_client)

    assert result[0]["recommendation"] == (
        "Restrict SSH access to trusted IP ranges."
    )
