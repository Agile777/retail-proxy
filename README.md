# Deprecated

This folder is intentionally not used.

- Render should deploy from the repository root.
- Use the root server entrypoint and docs instead:
	- `server.js` (repo root)
	- `package.json` (repo root)
	- `RENDER_DEPLOY_INSTRUCTIONS.md`
	- `SMS_API_SETUP.md`

If you start `render-deploy/server.js`, it will exit with an error to prevent accidentally deploying the wrong file.
