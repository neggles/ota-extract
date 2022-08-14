from importlib.metadata import version

release = version("ota-extract")
version = ".".join(release.split(".")[:2])
