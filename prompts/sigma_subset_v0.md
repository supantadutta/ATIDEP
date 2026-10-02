## Sigma subset you may use (version 0)

A rule outside this subset is rejected by the converter. Do not use anything not listed here.

Log source: exactly one of `category: process_creation`, `category: network_connection`, `category: dns_query`, with `product: windows`.

Fields: only the field names given to you for the log source. A rule using any other field name is rejected.

Value modifiers: none (exact match), `contains`, `startswith`, `endswith`, `re`, `all`, `windash`. Not allowed: `base64`, `base64offset`, `cidr`, `lt`, `lte`, `gt`, `gte`, `exists`, `fieldref`, `expand`.

Detection:
- Named selections are maps of `field|modifier: value-or-list`. Fields in one selection are combined with AND; a list of values is combined with OR (use `|all` for AND).
- `condition` may use `and`, `or`, `not`, `1 of selection*`, `all of selection*` and parentheses.
- Not allowed: `count`, `near`, `timeframe`, aggregation with `|`, and correlation rules.
- Matching is case-insensitive.
- Keep the rule narrow: use at least one condition that is specific to the behaviour described in the facts. A rule that matches only a generic file name or only a common tool is rejected.

Output keys you provide (the system adds `id`, `status`, `author`, `date` and `references`): `title`, `description`, `tags`, `logsource`, `detection`, `falsepositives`, `level` (one of informational, low, medium, high, critical).

`tags` must include the ATT&CK tags for the techniques given to you, in the form `attack.t1059.001` plus the tactic, for example `attack.execution`.
