CLI = .build/miximus_cli

all: $(CLI) test

$(CLI): .build
	make -C $(dir $@)

.build:
	mkdir -p $@
	cd $@ && cmake ../circuit/ || rm -rf ../$@

git-submodules:
	git submodule update --init --recursive

clean:
	rm -rf .build

python-test:
	make -C python test

solidity-test:
	make -C solidity test

test: .keys/miximus.pk.raw solidity-test python-test

.keys/miximus.pk.raw: $(CLI)
	mkdir -p $(dir $@)
	$(CLI) genkeys .keys/miximus.pk.raw .keys/miximus.vk.json
