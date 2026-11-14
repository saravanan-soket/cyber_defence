"""Turn real CVEs into defensive tasks (one builder per ecosystem).

Host side (no third-party code runs): fetch source, split the upstream fix
into reference patch + oracle tests, and write a task bundle.
Container side (inside Docker only): build the task image and confirm the
oracle by grading the upstream fix with the production grader.
"""
