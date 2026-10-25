def add_ai_recommendations(findings, ai_client):
    # prompt Claude, give context and tell it what to do
    for finding in findings:
        prompt = f"""
        You are assisting with an AWS security audit.

        Domain: {finding["domain"]}
        Resource ID: {finding["resource_id"]}
        Severity: {finding["severity"]}
        Threat Type: {finding["threat_type"]}
        Explanation: {finding["explanation"]}

        Provide one concise, actionable remediation recommendation.
        Use no more than 2 sentences.
        Do not include code blocks, numbered steps, or additional analysis.
        Return only the recommendation.
        """
        # API call
        message = ai_client.messages.create(
            model="claude-haiku-5-5",
            max_tokens=250,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
        )
        # print only text blocks, not thinking blocks
        for block in message.content:
            if block.type == "text":
                finding["recommendation"] = block.text

    # return augmented findings with AI recommendations
    return findings