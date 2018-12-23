CLI = .build/miximus_cli

all: $(CLI) test

$(CLI): release
	$(MAKE) -C $(dir $@)

.build:
	mkdir -p $@
	cd $@ && cmake ../circuit/ || rm -rf ../$@

debug:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Debug ../circuit/

release:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release ../circuit/

performance:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release -DPERFORMANCE=1 ../circuit/

git-submodules:
	git submodule update --init --recursive

clean:
	rm -rf .build

python-test:
	$(MAKE) -C python test

solidity-test:
	$(MAKE) -C solidity test

test: .keys/miximus.pk.raw solidity-test python-test

.keys/miximus.pk.raw: $(CLI)
	mkdir -p $(dir $@)
	$(CLI) genkeys .keys/miximus.pk.raw .keys/miximus.vk.json
