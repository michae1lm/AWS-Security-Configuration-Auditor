# Your project is ready to run

Michael, the source code, seven rules, offline examples, AWS collector, tests, documentation, and GitHub Actions workflow are included in this folder.

1. Extract the ZIP and keep the folder structure intact.
2. On Windows, double-click `RUN_DEMO.cmd` with Python 3.11+ installed.
3. Open `reports/demo/report.md` to inspect the generated results. The exit code 2 is intentional: the invented demo includes missing data.
4. Read `README.md` for test commands and `docs/demo_script.md` to prepare to explain the project.
5. Configure your AWS audit profile using `docs/aws_setup.md`, then run the live command from the README.

The offline demo needs no AWS account and no paid infrastructure. The live collector is implemented and tested with simulated API responses. Actual account validation is still pending; record your real observations in `docs/validation.md` after a live run.

The project has not been pushed to GitHub from this session. To publish it, follow `docs/github_publish.md`. A GitHub Actions workflow is included, but no hosted workflow result is claimed.

For your resume, use only wording you can demonstrate and explain. See `docs/resume_bullets.md`; do not claim a live audit, verified remediation, or measured time savings until you have done and recorded them.
