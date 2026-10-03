# Vulncat presentation and compatibility

Vulncat is the product name; Vulnerability Concatenator is the full name. The original
black-cat mark, warm light surfaces, dark surfaces, and restrained violet accents appear
on the shell, sign-in and setup pages. Page titles, API/MCP identities, new report labels,
download names, command help, launcher messages, package descriptions and current user
documentation use the product name. Historical validation records retain their original names.

The README cat matches one of three original CLI banners. An interactive launch chooses
one at random, so the same cat can appear on consecutive launches. Art goes only to stderr
when all three standard streams are terminals. `--quiet` and `--no-cat` suppress art;
errors and confirmation prompts remain visible. Redirected commands and all stdio MCP
launch paths emit no banners. Reports retain their data fields, provenance and safety checks.

Preferred entry points are `vulncat`, `vulncat-mcp` and `vulncat-worker`. Branded Windows
shortcuts wrap the same established scripts. Old shortcuts and commands remain available.
The distribution name, Python module, Compose project and volumes, database defaults,
cookie/event names, environment variables and MCP tool names remain compatible. Existing
stored report paths remain valid; only newly generated report filenames use the Vulncat prefix.
The repository is private `lpayt402/vulncat`. The reviewed source repository,
`lpayt402/vulnerability-workbench`, is preserved separately with its original history.

## Source labels and hypothetical examples

Product copy uses generic source categories. The [source format reference](offline-source-formats.md#source-labels-and-compatibility-identifiers)
maps those labels to existing API identifiers. Exact vendor format names, native namespaces,
parser fields and schema citations remain in technical references and format-selection guidance.
These identifiers describe supported mechanics; they do not describe an author's, employer's
or customer's tool stack. Dependencies and third-party attribution keep their correct names.

Examples model plausible hypothetical environments using synthetic records and documentation
addresses. Actual platform names and versions may illustrate a fingerprint; synthetic finding
and plugin IDs exercise parsers without asserting a vendor advisory. Sample mapping fields
are application-defined where native export schemas are unverified. Examples must not invent
products, adapters, supported fields or workflow steps.

## Verification scope

Banner tests exercise all three variants with JSON, CSV and Markdown output, redirected
streams, quiet aliases, and terminal-mode CLI MCP dispatch. Real SDK stdio tests verify
initialization, tool calls, structured exports, disabled writes and errors without protocol
contamination. Shell tests check the wordmark, full name, decorative cat and page title.

The attribution regression awaits the named dialog and an enabled paging control. Its
explicit target, disabled preview/apply controls, confirmation requirement, no premature
mutation, revision 4 and attribution version 2 assertions remain intact.

Local browser review uses only synthetic API fixtures for presentation: login, setup,
service exposure in light/dark mode and at a 390px mobile viewport. The separate CI
PostgreSQL/browser job validates real persistence, interfaces, exports, restore and undo.
Screenshots are saved in the isolated task checkout's ignored `output/playwright/` directory.
