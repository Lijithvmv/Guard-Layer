# Evaluation

GuardLayer is measured three ways, and every number here can be reproduced from the repository:

1. **Public prompt-injection datasets**: text-level precision, recall and false-positive rate on held-out data.
2. **An agentic evaluation**: a real model runs tool-using tasks with injections hidden in what it reads; scored by what
   the tools actually executed.
3. **[AgentDojo](#agentdojo)**: a third-party benchmark (ETH Zurich) with its own environments, tasks and attacks.

Where a result is *not* a fair test (for example, a model evaluated on data it was trained on, or rules written after
seeing the attacks), it says so.

--8<-- "README.md:evaluation"
