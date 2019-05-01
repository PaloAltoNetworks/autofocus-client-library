.PHONEY: test testsimple watch shell python test2 testsimple2 watch2 shell2 python2 2to3

cur_dir := $(notdir $(shell pwd))

test:
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base \
			   /opt/overwatch/env/bin/tox

testsimple:
	docker run --rm --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base \
			   /opt/overwatch/env/bin/tox

watch:
	fswatch -0 -o tests/test_*.py | xargs -0 -n 1 -I{} make testsimple

shell:
	# Run bash with active venv
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base \
			   /bin/bash -c "source /opt/overwatch/env/bin/activate;/bin/bash"

python:
	# Run venv python
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base \
			   /opt/overwatch/env/bin/python

cov:
	open -a "Google Chrome" tests/htmlcov/index.html

# Python 2-3 conversion targers below

test2:
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base:py2 \
			   /opt/overwatch/env/bin/tox -e py27

testsimple2:
	docker run --rm --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base:py2 \
			   /opt/overwatch/env/bin/tox -e py27

watch2:
	fswatch -0 -o tests/test_*.py | xargs -0 -n 1 -I{} make testsimple2

shell2:
	# Run bash with active venv
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base:py2 \
			   /bin/bash -c "source /opt/overwatch/env/bin/activate;/bin/bash"

python2:
	# Run venv python
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
		       -w /opt/overwatch/env/src/$(cur_dir) \
			   registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base:py2 \
			   /opt/overwatch/env/bin/python

2to3:
	# Run 2to3 against repo
	docker run --rm -it --mount src=$(shell pwd),target=/opt/overwatch/env/src/$(cur_dir),type=bind \
           -w /opt/overwatch/env/src/$(cur_dir) \
           registry.gsrt.paloaltonetworks.local:5000/gsrttech/playbooks_base:py2 \
           /usr/bin/2to3-2.7 --no-diffs -n -w $(ARGS)