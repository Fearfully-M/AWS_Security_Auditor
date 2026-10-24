rows = [
        {"name": "Alice", "severity": "High"},
        {"name": "Bob", "severity": "Low"},
    ]

html_rows = ""

for row in rows:
    html_rows += f"""
        <tr>
            <td>{row["name"]}</td>
            <td>{row["severity"]}</td>
        </tr>
    """

html = f"""
<html>
<body>
<table>
    <tr>
        <th>Name</th>
        <th>Severity</th>
    </tr>
    {html_rows}
</table>
</body>
</html>
"""  

print(html)