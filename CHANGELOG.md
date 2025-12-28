# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.8] - 2025-12-28

### Added

- Enhanced KEV handling and statistics tracking (#69)
- KEVVY commands section and improved admin commands documentation (#65)

### Fixed

- Restored `check_cisa_kev_feed` background task functionality that was accidentally removed (#135)
- Fixed throttling issues (#83)
- Downgraded Docker Python from 3.14 to 3.13 for package compatibility (#136)
- Applied security patches to Docker base image (CVE-2025-6965, CVE-2025-4802, CVE-2025-32988, CVE-2025-32990, CVE-2023-31484) (#137)
- Removed obsolete test references (#133)

### Changed

- Refactored DiagnosticsCog tests for web status updates (#70)
- Updated README to clarify CVE detection sources and configuration (#71)

### Dependencies

- Bumped `vulncheck-sdk` from 0.0.12 to 0.0.13
- Bumped `aiohttp` from 3.11.18 to 3.13.2
- Bumped `ruff` from 0.11.8 to 0.14.2
- Bumped `pytest` from 8.3.5 to 8.4.2
- Bumped `pytest-mock` from 3.14.0 to 3.14.1
- Bumped `pytest-asyncio` from 0.26.0 to 1.2.0
- Bumped `pytest-cov` from 6.1.1 to 7.0.0
- Bumped `urllib3` from 2.4.0 to 2.5.0
- Bumped `actions/checkout` from 4 to 6
- Bumped `actions/setup-python` from 5 to 6
- Bumped `github/codeql-action` from 3 to 4

## [0.2.7] - 2024-05-21

### Added

- New `/kevvy admin announce` command to send announcements to all servers
- Improved channel selection logic for announcements with fallback options
- New CHANGELOG.md to track future updates and releases

### Changed

- Enhanced code quality in the announcement feature
- Improved error handling and reporting for announcement delivery
- Better formatting of error messages and status updates
