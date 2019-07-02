APP_NAME=morty

build:
	docker rmi -f $(APP_NAME):latest
	docker build -t $(APP_NAME) .

run:
	@echo "\n /!\ DO NOT use in production\n"
	docker run --rm -t -i --net=host --name="$(APP_NAME)" $(APP_NAME)
