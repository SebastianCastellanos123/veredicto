import json

import pytest

from veredicto.llm import AnthropicLLM, LLMError, urllib_http


def ok_body(text="hola", i=10, o=5):
    return json.dumps({"content": [{"type": "text", "text": text}], "usage": {"input_tokens": i, "output_tokens": o}}).encode()


class FakeHttp:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, json.loads(body), timeout))
        return self.responses.pop(0)


def test_request_shape_and_response_parsing():
    http = FakeHttp((200, ok_body("resp", 11, 7)))
    llm = AnthropicLLM("clave-123", "modelo-x", http=http)
    res = llm.complete("sistema", "usuario", max_tokens=500)
    method, url, headers, payload, _ = http.calls[0]
    assert method == "POST" and url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "clave-123" and headers["anthropic-version"] == "2023-06-01"
    assert payload == {"model": "modelo-x", "max_tokens": 500, "system": "sistema",
                       "messages": [{"role": "user", "content": "usuario"}]}
    assert (res.text, res.input_tokens, res.output_tokens) == ("resp", 11, 7)


def test_retries_with_backoff_on_rate_limit():
    sleeps = []
    http = FakeHttp((429, b"{}"), (503, b"{}"), (200, ok_body()))
    llm = AnthropicLLM("k", http=http, sleep=sleeps.append)
    assert llm.complete("s", "u", max_tokens=10).text == "hola"
    assert len(http.calls) == 3 and sleeps == [1, 2]


def test_gives_up_after_retries():
    http = FakeHttp(*[(500, b"{}")] * 4)
    with pytest.raises(LLMError, match="HTTP 500"):
        AnthropicLLM("k", http=http, sleep=lambda s: None).complete("s", "u", max_tokens=10)
    assert len(http.calls) == 4


def test_client_errors_are_not_retried_and_never_leak_the_key():
    err = json.dumps({"error": {"type": "authentication_error", "message": "invalid x-api-key"}}).encode()
    http = FakeHttp((401, err))
    with pytest.raises(LLMError) as e:
        AnthropicLLM("SECRETA-12345", http=http).complete("s", "u", max_tokens=10)
    assert "401" in str(e.value) and "authentication_error" in str(e.value)
    assert "SECRETA-12345" not in str(e.value) and len(http.calls) == 1


@pytest.mark.parametrize("body", [b"no es json", b"{}", b'{"content": 5}', b'{"content": [1]}'])
def test_malformed_response_raises_clean_error(body):
    with pytest.raises(LLMError, match="formato inesperado"):
        AnthropicLLM("k", http=FakeHttp((200, body))).complete("s", "u", max_tokens=10)


def test_missing_key_and_non_https():
    for bad in ("", "   "):
        with pytest.raises(LLMError, match="clave"):
            AnthropicLLM(bad)
    with pytest.raises(LLMError, match="https"):
        urllib_http("GET", "http://insegura.example", {}, None, 1)
    with pytest.raises(LLMError, match="https"):
        urllib_http("GET", "file:///etc/passwd", {}, None, 1)
