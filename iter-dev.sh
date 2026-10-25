#!/bin/bash

ruff check -q *.py jkutils/*.py others/*.py tester/*.py && \
     hcli plugin lint . && \
     hcli plugin uninstall diaphora; hcli plugin install .
