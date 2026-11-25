# tandabill.world — landing site for TandaBill

Static, zero-framework landing page for [TandaBill](https://github.com/FluxNimbusAi/tanda): escrowed settlement between verified humans on World Chain.

## Rules of this repo (pre-ruled 2026-11-22)
- Plain HTML/CSS, no JS, no fonts/assets loaded remotely. Single file: `index.html`.
- Copy carries only what is true today (currently: World Chain Sepolia testnet, verified contracts, 41-assertion loop proofs). No filler, no mainnet or token claims.
- Template inspirations and layout law: `references/templates.md` (ideas captured, zero code copied).

## Deploy
Vercel project (org `fluxnimbusai`) imports this repo; domain `tandabill.world` attached owner-side. Nothing in this repo contains credentials; CI enforces that.
