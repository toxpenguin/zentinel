# Build: docker build -t zentinel/coraza-waf -f agents/coraza-waf/Dockerfile .
# (build context is the repository root — the agent builds against ../../sdk/go)
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY sdk/go ./sdk/go
COPY agents/coraza-waf ./agents/coraza-waf
WORKDIR /src/agents/coraza-waf
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coraza-waf .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/coraza-waf /usr/local/bin/coraza-waf
COPY --from=build /src/agents/coraza-waf/rules /etc/zentinel/waf-rules
USER nonroot:nonroot

# Mount your own rules over /etc/zentinel/waf-rules (or add another --rules
# path), and share /run/zentinel with the proxy so it can reach the socket.
ENTRYPOINT ["/usr/local/bin/coraza-waf"]
CMD ["--socket", "/run/zentinel/coraza-waf.sock", "--rules", "/etc/zentinel/waf-rules"]
