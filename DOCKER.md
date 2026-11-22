# Docker run guide

Docker packages the same offline educational prototype. It does not add AWS access, IAM coverage or proof of exploitation. Initial code was AI-assisted. These instructions do not claim personal testing by the maintainer.

Run commands from the repository root with Docker installed and running. The shell examples use POSIX syntax (Linux, macOS or WSL).

## Build and show help

```sh
docker build --pull -t iam-pathfinder:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges iam-pathfinder:local
```

The default command shows help. Pass CLI arguments after the image name. The image runs as numeric non-root user `65532:65532` and includes only source and fictional examples. No pip installation is needed at runtime.

The base tag is mutable, not a pinned or vulnerability-free artifact. Rebuild for base updates; scan and review the resulting image before use. Building downloads a base image. `--network none` applies to the running container, not the build.

## Run the fictional snapshot

```sh
status=0
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  iam-pathfinder:local examples/snapshot.json || status=$?
printf 'Exit code: %s\n' "$status"
test "$status" -eq 3
```

This fictional input is expected to return `3`, meaning a candidate path exists, not a container failure or verified exploit. The final `test` checks that expectation. General exit codes are `0` (no candidate within the model), `2` (input/file error), and `3` (candidate found). Docker itself can return other codes, for example when startup fails.

## Read a private export and save a report

Keep exports and reports outside this repository. Do not pass AWS credentials or mount your home directory or Docker socket. The tool only needs the input files.

```sh
mkdir -p "$HOME/iam-pathfinder-private/input" "$HOME/iam-pathfinder-private/output"
# Put your complete export at:
# $HOME/iam-pathfinder-private/input/auth.json
status=0
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$HOME/iam-pathfinder-private/input,dst=/input,readonly" \
  --mount "type=bind,src=$HOME/iam-pathfinder-private/output,dst=/output" \
  iam-pathfinder:local /input/auth.json --aws-export \
  --report /output/report.md || status=$?
printf 'Exit code: %s\n' "$status"
```

Inspect the exit code, stderr and report warnings together. The output mount is writable even though the container root filesystem is read-only. On Linux, the explicit user matches file ownership to your host account; do not run the example with `sudo`. Host permissions, Docker Desktop sharing and SELinux may need local adjustment. Do not solve permission errors by making private IAM data world-readable.

## JSON and graph output

```sh
# Save stdout and keep stderr separate. Review the exit code as above.
docker run --rm --network none --read-only iam-pathfinder:local \
  examples/snapshot.json --json > paths.json

docker run --rm --network none --read-only iam-pathfinder:local \
  examples/snapshot.json --dot > graph.dot
# Graphviz is a separate host tool, not installed in this image.
dot -Tpng graph.dot -o graph.png
```

The two Docker commands above normally return `3` for this fixture. In scripts using `set -e`, handle that expected status explicitly, as in the snapshot example. Real-account outputs are sensitive and must stay private.

## Run the tests in a separate image

```sh
docker build --pull --target test -t iam-pathfinder:test .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m iam-pathfinder:test
```

The temporary filesystem allows tests to create disposable input files without writing to the image. The `test` target includes the test suite. The default final image does not. The Docker workflow builds both targets, runs the tests, checks help and checks the fictional snapshot's exit status. Its current run result, not this guide, is the evidence of whether those checks passed. It does not test a real AWS account or every host platform.
