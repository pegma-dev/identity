# Contributing

Read [AGENTS.md](AGENTS.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing the package.
Pull requests must pass the complete gate on Node.js 22 and 24:

```sh
pnpm install --frozen-lockfile
pnpm run format:check
pnpm run check
pnpm test
pnpm audit --prod --audit-level=high
```

`pnpm test` starts Azurite. Identity uniqueness, repair, challenge consumption,
and counter transitions must agree between the memory store and the real
adapter where storage races are involved.
