# HooshiXAgent Executable Runtime Gate

**Status:** Normative

Unit tests, integration tests, static analysis, compilation, and smoke tests are necessary where applicable, but they do not replace execution of a capability once that capability is runnable.

## 1. Trigger

Whenever a capability becomes runnable, the real capability MUST be executed before the leaf can PASS.

Examples of runtime-gate triggers include:

- Gateway process starts;
- an HTTP/API route becomes functional;
- Agent authenticates;
- authorization/enrollment material can be consumed;
- a tunnel session opens;
- stream multiplexing works;
- a local service exposure command works;
- public ingress routes;
- an OS service installs;
- reboot persistence works;
- an updater can apply an update;
- a deployment package/Compose stack can start.

If runtime testing is technically possible but is skipped, the applicable leaf cannot PASS.

## 2. Runtime evidence requirements

Runtime evidence must identify:

- the executable/capability exercised;
- environment and dependency setup relevant to the result;
- command or reproducible procedure used;
- expected positive behavior;
- applicable negative/failure behavior;
- observed result;
- restart/reconnect/persistence behavior when part of the leaf;
- secrets/PII handling;
- any checks that were Not run or Partially verified.

A log statement claiming startup is not a substitute for exercising the capability.

## 3. Tunnel runtime example

When the Agent/Gateway path becomes runnable, an applicable gate is:

```text
start approved local test service
start real Gateway
start real Edge Agent
apply deterministic authorized device/session/endpoint fixture
establish authenticated Agent session
send a real public/staging request through the Gateway
verify the approved local service receives it
compare expected local/public response behavior
interrupt the connection
verify reconnect/recovery
```

Mocks may stand in for the separate external Control Panel contract when the active leaf permits it, but mocks do not replace the real Agent and Gateway processes when those processes are the capability under test.

## 4. Service/deployment runtime example

When a service or deployment package becomes runnable, applicable evidence includes:

```text
start the real packaged process/deployment
exercise readiness/health
exercise at least one real critical path
exercise an applicable invalid/failure path
restart the process/deployment
verify expected recovery/persistence
```

## 5. Completion rule

The following alone are insufficient completion evidence when a real runtime gate applies:

```text
code exists
it compiles
unit tests pass
integration tests pass
static/security scans pass
PR is open
CI is green
PR is approved
```

Completion still requires the applicable real runtime evidence plus the project's PR/merge/post-merge requirements.

## 6. Non-runnable leaves

A governance/documentation-only leaf that introduces no executable capability may mark the Executable Runtime Gate as `Not applicable`, with the reason recorded in evidence.

`Not applicable` MUST NOT be used when a real capability is runnable and technically testable.
