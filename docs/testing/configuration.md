# Configuration and reload

## Scope

Loading the configuration file: defaults, validation, and the example
configuration shipped; and reloading on SIGHUP: what applies at once,
what needs a restart, and a broken file.

## Risks

- An invalid configuration accepted, or a valid one refused.
- Wrong defaults.
- A reload that applies part of a change, or stops the server on a broken
  file.

## Approach

- **Unit:** loading every section with its defaults and refusals, the
  shipped example configuration staying valid, what needs a restart, and
  SIGHUP becoming a reload request.
- **Integration:** reload changing the access rules without a restart,
  ignoring a broken file, and reporting what needs a restart.
- **E2E:** `TestReloadApplies`: a domain added to `acme.allowed_domains`
  gets a certificate after SIGHUP, without a restart; a restart-only
  change is reported while the server goes on. `TestServerLifecycle`
  (Operations) reloads a broken and a good file.

## Known gaps

- Of the settings a reload applies, only the ACME domains are tested end
  to end.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
17 test cases: 13 unit, 3 integration, 1 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestNeedsRestart` | Unit | Which changes a reload applies (access rules, ACME domains) and which need a restart (listening address, server names, data directory, identity provider, ACME or SCEP switched off or on). | [cmd/bxp/reload_test.go](../../cmd/bxp/reload_test.go) |
| `TestHangupBecomesAReloadRequest` | Unit | "systemctl reload bastionxp-ca" sends SIGHUP. It must turn into a reload request, and must not stop the program. | [cmd/bxp/reload_unix_test.go](../../cmd/bxp/reload_unix_test.go) |
| `TestACMELimits` | Unit | The ACME rate limits: defaults, one set alone, and zero for no limit. (1 sub-case) | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestCALifetimes` | Unit | The root and intermediate lifetimes: 10 and 3 years by default, set in years or days; refused without a unit, not positive, above 30 years, with an unknown unit, below a year, or an intermediate that outlives the root. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestExampleConfigIsValid` | Unit | The example configuration in the repository loads. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadACME` | Unit | The ACME allowed domains are read from the configuration. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadAppliesDefaults` | Unit | Loading a minimal configuration fills in the defaults: ECDSA keys, the CA name, the server address and names. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadLDAP` | Unit | LDAP needs no server.url, and gets the Active Directory defaults. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadOIDC` | Unit | OIDC settings and access rules are read, with the default claims and scopes; a provider on this machine may use plain HTTP, for tests. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadPublicAddress` | Unit | The public HTTP address and URL are read from the configuration. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadRejectsBadConfig` | Unit | Every invalid configuration is refused with a message that names the setting: unknown keys, missing required settings, bad server and public URLs, bad ACME domains, IP ranges, resolvers, limits and challenges, access rules that name nobody or give nothing, incomplete or unsafe OIDC and LDAP settings, a key passphrase inside the data directory, bad metrics settings, names outside the name constraints, bad SCEP static settings and an unknown key type. (1 sub-case) | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestLoadSCEP` | Unit | SCEP is on when enabled, and off unless configured. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestSCEPStaticDefaultsToDeviceProfile` | Unit | SCEP with a static password uses the tls-device profile by default, which logins may also hand out. | [internal/config/config_test.go](../../internal/config/config_test.go) |
| `TestReloadChangesTheRulesWithoutARestart` | Integration | A reload changes the access rules without a restart, and the log says so. | [cmd/bxp/reload_test.go](../../cmd/bxp/reload_test.go) |
| `TestReloadIgnoresABrokenConfiguration` | Integration | A broken file must not take the CA down, nor change its rules. (1 sub-case) | [cmd/bxp/reload_test.go](../../cmd/bxp/reload_test.go) |
| `TestReloadReportsWhatNeedsARestart` | Integration | A reload that changes a setting needing a restart names it in the log. | [cmd/bxp/reload_test.go](../../cmd/bxp/reload_test.go) |
| `TestReloadApplies` | E2E | A reload (SIGHUP) applies what it says it applies, at once: an ACME domain allowed by the new configuration works without a restart. A change that needs a restart is reported, and the server goes on as it was. | [test/e2e/reload_test.go](../../test/e2e/reload_test.go) |
<!-- END GENERATED CASES -->
