# gzilla
A visual packet spoofing tool

## The Docker containers
### Building
- `docker-compose build`
- Or individually by specifying a service: `docker-compose build attacker`
### Running
- `docker-compose run attacker`
- `docker-compose run apollo`

### Testing
- `pytest /tests -v --disable-pytest-warnings`
