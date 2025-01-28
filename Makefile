up:
	export BUILDKIT_PROGRESS=plain &&\
	docker compose build && docker compose up 

down:
	docker compose down

delete:
	docker compose down -v
