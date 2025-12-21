# Testing Guide for Developers

This guide covers testing strategies, patterns, and workflows for the Sagemcom API.

## Overview

The test suite uses `pytest` with async support to validate the client's behavior against mocked Sagemcom router API responses. Tests are split into:

- **Unit tests** (`tests/unit/`) - Mock-based tests for individual methods, error handling, and encryption
- **Integration tests** (`tests/integration/`) - Tests against real or comprehensive simulated router APIs (requires device access)
- **Fixtures** (`tests/fixtures/`) - Sample API response payloads from different router models

## Running Tests (from Dev Container)

```bash
# Run all tests
poetry run pytest

# Run only unit tests
poetry run pytest tests/unit/

# Run with coverage report
poetry run pytest --cov=sagemcom_api

# Run with coverage HTML report
poetry run pytest --cov=sagemcom_api --cov-report=html

# Run specific test file
poetry run pytest tests/unit/test_client_basic.py

# Run specific test
poetry run pytest tests/unit/test_client_basic.py::test_login_success
```

## Test Structure

### Mocking Strategy

We mock at the **`aiohttp.ClientSession.post`** level to:
- Simulate realistic HTTP interactions
- Test full request/response cycle including JSON encoding/decoding
- Validate request payload structure
- Control response status codes and payloads

### Fixture Patterns

All fixtures are defined in `tests/conftest.py` with **function scope** for test isolation:

- **`mock_session_factory`** - Factory for creating mock aiohttp sessions with custom responses
- **`login_success_response`** - Mock response for successful login
- **`login_auth_error_response`** - Mock response for authentication failure
- **`mock_client_...`** - Pre-configured SagemcomClient with mocked session

Example usage:
```python
@pytest.mark.asyncio
async def test_example(mock_session_factory, login_success_response):
    mock_session = mock_session_factory([login_success_response])
    client = SagemcomClient("192.168.1.1", "admin", "password",
                           EncryptionMethod.MD5, session=mock_session)
    # Test implementation...
```

### API Response Fixtures

Realistic API responses are stored in `tests/fixtures/` as JSON files mirroring actual router responses:

- `login_success.json` - Successful login with session_id and nonce
- `login_auth_error.json` - Authentication failure (XMO_AUTHENTICATION_ERR)
- `device_info.json` - Device information response
- `hosts.json` - Connected devices list
- `xpath_value.json` - Generic XPath query response

These fixtures preserve the actual JSON-RPC structure from Sagemcom routers:
```json
{
  "reply": {
    "error": {"description": "XMO_REQUEST_NO_ERR"},
    "actions": [{
      "callbacks": [{
        "parameters": {"id": 12345, "nonce": "abcdef123456"}
      }]
    }]
  }
}
```

## Testing Patterns

### 1. Testing Authentication

All three encryption methods (MD5, SHA512, MD5_NONCE) must be tested. See `test_client_basic.py` for examples:

```python
@pytest.mark.asyncio
async def test_login_success(mock_session_factory, login_success_response):
    """Test successful login flow."""
    # Demonstrates mocking login with session_id/nonce exchange
```

### 2. Testing Error Handling

Each `XMO_*_ERR` constant should have corresponding test cases:

```python
@pytest.mark.asyncio
async def test_authentication_error(mock_session_factory, login_auth_error_response):
    """Test AuthenticationException is raised on XMO_AUTHENTICATION_ERR."""
    # Demonstrates error response mocking
```

### 3. Testing XPath Operations

Validate URL encoding with safe characters preserved:

```python
@pytest.mark.asyncio
async def test_xpath_url_encoding(mock_session_factory):
    """Test XPath values are URL-encoded with /=[]' preserved."""
    # Demonstrates XPath encoding validation
```

### 4. Testing Sequential Responses

Most API operations require multiple HTTP requests (login → operation). Use `mock_session_factory` with response lists:

```python
# Two sequential responses
mock_session = mock_session_factory([login_success_response, xpath_value_response])

await client.login()              # Consumes login_success_response (1st call)
await client.get_value_by_xpath() # Consumes xpath_value_response (2nd call)
await client.logout()             # Would raise StopIteration (no 3rd response)
```

## Adding New Tests

### For a new unit test:

1. Determine what you're testing (method, error case, encryption variant)
2. Create or reuse fixture for API response in `tests/fixtures/`
3. Create test file in `tests/unit/test_<module>.py`
4. Use `mock_session_factory` to inject responses
5. Write assertions for both success and error paths
6. Run test with coverage to verify new lines are covered

### For a new integration test:

1. Document router model and firmware version in test docstring
2. Create test in `tests/integration/test_<feature>.py`
3. Add conditional skip if router not available: `@pytest.mark.skipif(...)`
4. Use real credentials from environment variables, not hardcoded

## Test Coverage

Run coverage reports regularly:
```bash
poetry run pytest --cov=sagemcom_api --cov-report=term-missing
```

The `--cov-report=term-missing` shows which lines lack coverage.
