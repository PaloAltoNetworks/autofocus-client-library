.PHONEY: test

cur_dir := $(notdir $(shell pwd))

test:
	docker run --rm -it --mount src=$(shell pwd),target=/tmp/$(cur_dir),type=bind \
			   -v ~/.config/panw:/root/.config/panw \
		       -w /tmp/$(cur_dir) \
			   docker-gsrt-tech.af.paloaltonetworks.local/base-image/gitlabci:latest \
			   tox


shell:
	# Run bash with active venv
	docker run --rm -it --mount src=$(shell pwd),target=/tmp/$(cur_dir),type=bind \
			   -v ~/.config/panw:/root/.config/panw \
		       -w /tmp/$(cur_dir) \
			   docker-gsrt-tech.af.paloaltonetworks.local/base-image/gitlabci:latest \
			   /bin/bash -c "/bin/bash"

python:
	# Run venv python
	docker run --rm -it --mount src=$(shell pwd),target=/tmp/$(cur_dir),type=bind \
			   -v ~/.config/panw:/root/.config/panw \
		       -w /tmp/$(cur_dir) \
			   docker-gsrt-tech.af.paloaltonetworks.local/base-image/gitlabci:latest \
			   python3

cov:
	open -a "Google Chrome" tests/htmlcov/index.html
