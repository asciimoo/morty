APP_NAME=dalf/morty

build:
	docker rmi -f $(APP_NAME):latest
	docker build -t $(APP_NAME) .

run:
	@echo "\n /!\ DO NOT use in production\n"
	docker run --rm -t -i --net=host --name="morty" $(APP_NAME)
