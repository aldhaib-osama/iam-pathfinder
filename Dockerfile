FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app
COPY LICENSE /app/LICENSE
COPY src/ /app/src/
COPY examples/ /app/examples/

USER 65532:65532
ENTRYPOINT ["python", "-m", "iampathfinder.cli"]
CMD ["--help"]

FROM runtime AS test
COPY tests/ /app/tests/
ENTRYPOINT ["python", "-m", "unittest", "discover", "-s", "/app/tests", "-v"]
CMD []

FROM runtime AS final
