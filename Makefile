# Makefile — convenience targets for the rebuilding_tls project.
#
# All targets are meant to be run from the repository root.
# Server and client live in separate processes, so you need TWO terminals
# for any client/server demo.

PYTHON ?= python3

.PHONY: help install \
        part4 part4-certs part4-server part4-client \
        part1-demo part2-demo \
        clean-part4-certs

help:
	@echo "Available targets:"
	@echo ""
	@echo "  install            Install Python dependencies (cryptography)."
	@echo ""
	@echo "  part4-certs        Generate the Part 4 certificate chain (run once)."
	@echo "  part4-server       Start the Part 4 authenticated server."
	@echo "                     Run in TERMINAL 1."
	@echo "  part4-client       Connect with the Part 4 authenticating client."
	@echo "                     Run in TERMINAL 2 (after part4-server is up)."
	@echo "  part4              Alias of part4-certs."
	@echo ""
	@echo "  part1-demo         Run the Part 1 CTR malleability attack demo."
	@echo "  part2-demo         Run the Part 2 HMAC tampering rejection demo."
	@echo ""
	@echo "  clean-part4-certs  Remove generated Part 4 certificate files."
	@echo ""
	@echo "NOTE: Server/client demos require two terminals. There is no"
	@echo "      single-command target for them on purpose."

install:
	$(PYTHON) -m pip install -r requirements.txt

# ── Part 4 ────────────────────────────────────────────────────────────

part4-certs:
	$(PYTHON) part_4/implementation/setup_certificates.py

part4-server:
	$(PYTHON) part_4/implementation/server_v4.py

part4-client:
	$(PYTHON) part_4/implementation/client_v4.py

# Convenience alias: same as part4-certs (the only step that runs to
# completion without needing a second terminal).
part4: part4-certs

clean-part4-certs:
	rm -rf part_4/implementation/certs

# ── Standalone attack demos (single command, no second terminal) ──────

part1-demo:
	$(PYTHON) part_1/ctr_malleability_demo.py

part2-demo:
	$(PYTHON) part_2/tampering_demo_hmac.py
