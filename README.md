# Docker registry cleaner

I was missing tool to cleanup docker registry from old tags. So I made one.

This tool scans docker registry and cleans tags based on specified rules, which can be per-repository or global.

## Example

```
$ docker-registry-cleaner.py --registry_url=http://my-docker-registry:5000/ --rules_configuration_file rules.yaml
```

For more information of available configuration option, see `docker-registry-cleaner.py --help`.

## Rules configuration

The rules configuration file is written in YAML format. See included example `rules.yaml` for reference.

The file is validated against schema defined in `docker-registry-cleaner.yaml`.

## Docker

Of course, this tool can be run using docker. Dockerfile is included, so you can build your own image:

```
docker build -t docker-registry-cleaner .
```

and then run it:

```
docker run -it -e REGISTRY_URL=http://my-docker-registry:5000/ -v $(pwd)/rules.yaml:/app/rules.yaml docker-registry-cleaner
```

Each configuration option can be specified as environment variable. There is (incomplete) list of available
environment variables:

- `REGISTRY_URL` Specify URL of the docker registry. For example `http://my-docker-registry:5000/`
- `REGISTRY_VALIDATE_SSL` Set to `false` if you do not wish to validate SSL certificate of the registry.
- `RULES_CONFIGURATION_FILE` Path to `rules.yaml` file.
- `PUSHGATEWAY_URL` URL of Prometheus Pushgateway to push metrics about discarded and kept tags.
- `LOG_LEVEL` Specify logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. Defaults to `DEBUG` which logs everything.
- `DRY_RUN` Set to `true` to just print what would be done without actually removing anything.

To list all available configuration option, execute:

```
docker run -it docker-registry-cleaner --help
```

**REMEMBER: Do not forget to run garbage-collect for your registry when this tool is finished.**