# Autonomous Deployment Agent

This file outlines how an AI agent should manage deployment tasks for this project.

## Goals
- Build, test, and deploy the application automatically.
- Run tasks in parallel where possible to speed up the pipeline.
- Continuously monitor the repository for new commits and redeploy.

## Pipeline Outline
1. **Build**: Use Docker BuildKit to build the multi-stage image.
2. **Test**: Run unit tests via `python -m unittest` inside the Docker image.
3. **Deploy**: If tests succeed, deploy to Firebase Hosting using `firebase deploy`.
4. **Loop**: Check for new commits at regular intervals and repeat the process.

## Parallelization
- Leverage GNU `parallel` or multiple Docker build stages to run independent tasks concurrently (e.g., building frontend and backend).
- Run Cypress tests in parallel containers for faster feedback.

## Monitoring
- Log all actions and notify `iparther@gmail.com` on failures.
- Automatically retry failed deployments up to three times before notifying the admin.

## Security Notes
- Use Google OAuth2 for authentication.
- Keep secrets in `.env` files (never commit them).

