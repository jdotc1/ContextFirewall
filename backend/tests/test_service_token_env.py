"""Service token variables must not persist low-entropy credentials in memory."""

from app.firewall.secrets import find_secrets, has_secret, redact_text


def test_service_tokens_redact_short_and_quoted_values():
    for line in (
        "VAULT_TOKEN=x",
        "export GITHUB_TOKEN='readable token with spaces'",
        'AWS_SESSION_TOKEN="multi word credential"',
        "GITHUB_TOKEN=abc",
    ):
        raw = line + "\nkeep=visible"
        assert any(f.kind == "service_token_env" for f in find_secrets(raw)), line
        redacted = redact_text(raw)
        assert redacted.endswith("«REDACTED:service_token_env»\nkeep=visible")
        assert not has_secret(redacted)


def test_truncated_service_token_quote_is_redacted_through_line_end():
    text = 'VAULT_TOKEN="a phrase with no closing quote\nkeep=visible'
    assert redact_text(text) == "«REDACTED:service_token_env»\nkeep=visible"


def test_service_token_env_ignores_placeholders_and_similar_names():
    for text in (
        "VAULT_TOKEN=${VAULT_TOKEN}",
        "GITHUB_TOKEN=${GITHUB_TOKEN}",
        "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}",
        "MY_VAULT_TOKEN=visible",
        "VAULT_TOKEN_HINT=visible",
        "GITHUB_TOKEN=",
    ):
        assert all(f.kind != "service_token_env" for f in find_secrets(text)), text
