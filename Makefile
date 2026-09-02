FIXTURE := fixtures/overprivileged-agent

.PHONY: test lint fixture-plan

test:
	pytest -q

lint:
	ruff check . && ruff format --check .

# Regenerate the checked-in Terraform plan JSON. Needs no credentials and deploys nothing.
fixture-plan:
	cd $(FIXTURE)/terraform && terraform init -input=false >/dev/null \
	  && terraform plan -input=false -out=tfplan >/dev/null \
	  && terraform show -json tfplan > ../plan.json && rm -f tfplan
	@echo "wrote $(FIXTURE)/plan.json"
	cd fixtures/nested-modules/terraform && terraform init -input=false >/dev/null \
	  && terraform plan -input=false -out=tfplan >/dev/null \
	  && terraform show -json tfplan > ../plan.json && rm -f tfplan
	@echo "wrote fixtures/nested-modules/plan.json"
