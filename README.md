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

## Lab testing
### Lab 2:
- Attacker: `python3 gzilla/gzilla.py tests/lab2/dns_cache_poisoning.yaml`
- Apollo: `rndc dumpdb -cache && sleep 1 && cat /var/cache/bind/dump.db | grep ns.dnslabattacker.net`

## Installing requirements

`python3 -m pip install -r requirements.txt`

## Running the GUI

`python3 gzilla/main.py` 
