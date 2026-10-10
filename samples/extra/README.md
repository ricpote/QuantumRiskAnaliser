# Extra fixtures (ours)

Put new test inputs here (pcaps generated with OpenSSL >= 3.5 / Go 1.24, extra code patterns,
nginx/sshd/Terraform configs). Every fixture gets expectations in `tests/ground_truth.json`
so `make test` keeps proving 100% accuracy. Never edit `samples/official/`.
