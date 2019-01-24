all: lint compile test

compile:
	npm run compile

node_modules:
	npm install

.PHONY: test
test: node_modules
	npm run test

lint:
	npm run lint
