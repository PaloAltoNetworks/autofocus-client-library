.PHONEY: test testsimple watch shell python

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
