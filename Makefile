.PHONY: test
test:
	crystal spec

.PHONY: docs
docs:
	crystal docs
	rm -rf docs
	mv doc docs
