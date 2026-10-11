# Test fixtures

`api/` and `enrichment/` contain synthetic profiles (`alice`, `example.test`) used by offline tests.

`test_untrusted_tls_certificate_is_error_without_verdict` needs a throwaway self-signed certificate.
Private keys are git-ignored, so generate one locally before running that test:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost"   -keyout tests/fixtures/untrusted-test-key.pem -out tests/fixtures/untrusted-test-cert.pem
```

Without these files the test is skipped with an explicit reason.
